const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ 
    status: 'online',
    message: 'ETEC Messaging API is running!',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const { data: teacher, error } = await supabase
      .from('app_teachers')
      .select('id, name, email, password_hash, is_active')
      .eq('email', email)
      .maybeSingle();

    if (error || !teacher) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!teacher.is_active) {
      return res.status(401).json({ error: 'Account is inactive' });
    }

    const validPassword = await bcrypt.compare(password, teacher.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: teacher.id, email: teacher.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    await supabase
      .from('app_auth_tokens')
      .insert({
        teacher_id: teacher.id,
        token: token,
        expires_at: expiresAt.toISOString()
      });

    res.json({
      token,
      teacher: {
        id: teacher.id,
        name: teacher.name,
        email: teacher.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/verify', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(401).json({ error: 'Token is required' });
    }

    const { data: authToken, error } = await supabase
      .from('app_auth_tokens')
      .select('teacher_id, expires_at')
      .eq('token', token)
      .maybeSingle();

    if (error || !authToken) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    if (new Date(authToken.expires_at) < new Date()) {
      return res.status(401).json({ error: 'Token expired' });
    }

    const { data: teacher, error: teacherError } = await supabase
      .from('app_teachers')
      .select('id, name, email')
      .eq('id', authToken.teacher_id)
      .maybeSingle();

    if (teacherError || !teacher) {
      return res.status(401).json({ error: 'Teacher not found' });
    }

    res.json({ teacher });
  } catch (error) {
    console.error('Verify error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/messages', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: authToken, error: authError } = await supabase
      .from('app_auth_tokens')
      .select('teacher_id')
      .eq('token', token)
      .maybeSingle();

    if (authError || !authToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const teacherId = authToken.teacher_id;

    const { data: groupIds, error: groupError } = await supabase
      .from('app_group_members')
      .select('group_id')
      .eq('teacher_id', teacherId);

    const groupIdList = groupIds?.map(g => g.group_id) || [];

    let query = supabase
      .from('app_messages')
      .select(`
        id,
        title,
        content,
        image_url,
        document_url,
        created_at,
        sent_to_all,
        sent_by,
        app_message_individual_recipients!left(teacher_id),
        app_message_group_recipients!left(group_id)
      `)
      .order('created_at', { ascending: false });

    if (groupIdList.length > 0) {
      query = query.or(`sent_to_all.eq.true,app_message_individual_recipients.teacher_id.eq.${teacherId},app_message_group_recipients.group_id.in.(${groupIdList.join(',')})`);
    } else {
      query = query.or(`sent_to_all.eq.true,app_message_individual_recipients.teacher_id.eq.${teacherId}`);
    }

    const { data: messages, error: messagesError } = await query;

    if (messagesError) {
      console.error('Messages error:', messagesError);
      return res.status(500).json({ error: 'Error fetching messages' });
    }

    const { data: readStatus } = await supabase
      .from('app_message_read_status')
      .select('message_id, read_at')
      .eq('teacher_id', teacherId);

    const messagesWithReadStatus = (messages || []).map(message => ({
      ...message,
      is_read: readStatus?.some(rs => rs.message_id === message.id && rs.read_at !== null) || false
    }));

    res.json(messagesWithReadStatus);
  } catch (error) {
    console.error('Messages error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/messages/:messageId/read', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const { messageId } = req.params;

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: authToken, error: authError } = await supabase
      .from('app_auth_tokens')
      .select('teacher_id')
      .eq('token', token)
      .maybeSingle();

    if (authError || !authToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const teacherId = authToken.teacher_id;

    await supabase
      .from('app_message_read_status')
      .upsert({
        message_id: messageId,
        teacher_id: teacherId,
        read_at: new Date().toISOString()
      }, {
        onConflict: 'message_id,teacher_id'
      });

    res.json({ success: true });
  } catch (error) {
    console.error('Mark as read error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/groups/my', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: authToken, error: authError } = await supabase
      .from('app_auth_tokens')
      .select('teacher_id')
      .eq('token', token)
      .maybeSingle();

    if (authError || !authToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: groups, error: groupsError } = await supabase
      .from('app_group_members')
      .select(`
        group_id,
        app_message_groups!inner (
          id,
          name,
          description
        )
      `)
      .eq('teacher_id', authToken.teacher_id);

    if (groupsError) {
      console.error('Groups error:', groupsError);
      return res.status(500).json({ error: 'Error fetching groups' });
    }

    const groupIds = groups.map(g => g.group_id);
    let memberCounts = {};

    if (groupIds.length > 0) {
      const { data: counts } = await supabase
        .from('app_group_members')
        .select('group_id')
        .in('group_id', groupIds);

      if (counts) {
        counts.forEach(c => {
          memberCounts[c.group_id] = (memberCounts[c.group_id] || 0) + 1;
        });
      }
    }

    const result = groups.map(g => ({
      id: g.app_message_groups.id,
      name: g.app_message_groups.name,
      description: g.app_message_groups.description || '',
      member_count: memberCounts[g.group_id] || 1,
      is_member: true
    }));

    res.json(result);
  } catch (error) {
    console.error('My groups error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/groups/available', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: authToken, error: authError } = await supabase
      .from('app_auth_tokens')
      .select('teacher_id')
      .eq('token', token)
      .maybeSingle();

    if (authError || !authToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: myGroups } = await supabase
      .from('app_group_members')
      .select('group_id')
      .eq('teacher_id', authToken.teacher_id);

    const myGroupIds = myGroups?.map(g => g.group_id) || [];

    let query = supabase
      .from('app_message_groups')
      .select('id, name, description');

    if (myGroupIds.length > 0) {
      query = query.not('id', 'in', `(${myGroupIds.join(',')})`);
    }

    const { data: groups, error: groupsError } = await query;

    if (groupsError) {
      console.error('Available groups error:', groupsError);
      return res.status(500).json({ error: 'Error fetching groups' });
    }

    const groupIds = groups.map(g => g.id);
    let memberCounts = {};

    if (groupIds.length > 0) {
      const { data: counts } = await supabase
        .from('app_group_members')
        .select('group_id')
        .in('group_id', groupIds);

      if (counts) {
        counts.forEach(c => {
          memberCounts[c.group_id] = (memberCounts[c.group_id] || 0) + 1;
        });
      }
    }

    const result = groups.map(g => ({
      id: g.id,
      name: g.name,
      description: g.description || '',
      member_count: memberCounts[g.id] || 1,
      is_member: false
    }));

    res.json(result);
  } catch (error) {
    console.error('Available groups error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/groups', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const { name, description } = req.body;

    if (!name || name.trim().isEmpty) {
      return res.status(400).json({ error: 'Group name is required' });
    }

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: authToken, error: authError } = await supabase
      .from('app_auth_tokens')
      .select('teacher_id')
      .eq('token', token)
      .maybeSingle();

    if (authError || !authToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const groupData = {
      name: name.trim(),
      description: (description || '').trim()
    };

    const { data: group, error: groupError } = await supabase
      .from('app_message_groups')
      .insert(groupData)
      .select()
      .single();

    if (groupError) {
      console.error('Error creating group:', groupError);
      return res.status(500).json({ error: 'Error creating group' });
    }

    const { error: memberError } = await supabase
      .from('app_group_members')
      .insert({
        group_id: group.id,
        teacher_id: authToken.teacher_id
      });

    if (memberError) {
      console.error('Error adding member:', memberError);
      await supabase.from('app_message_groups').delete().eq('id', group.id);
      return res.status(500).json({ error: 'Error adding member to group' });
    }

    res.status(201).json({
      id: group.id,
      name: group.name,
      description: group.description || '',
      member_count: 1,
      is_member: true
    });
  } catch (error) {
    console.error('Create group error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/groups/:groupId/join', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const { groupId } = req.params;

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: authToken, error: authError } = await supabase
      .from('app_auth_tokens')
      .select('teacher_id')
      .eq('token', token)
      .maybeSingle();

    if (authError || !authToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { error: insertError } = await supabase
      .from('app_group_members')
      .insert({
        group_id: groupId,
        teacher_id: authToken.teacher_id
      });

    if (insertError) {
      return res.status(500).json({ error: 'Error joining group' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Join group error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/groups/:groupId/leave', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const { groupId } = req.params;

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: authToken, error: authError } = await supabase
      .from('app_auth_tokens')
      .select('teacher_id')
      .eq('token', token)
      .maybeSingle();

    if (authError || !authToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { error: deleteError } = await supabase
      .from('app_group_members')
      .delete()
      .eq('group_id', groupId)
      .eq('teacher_id', authToken.teacher_id);

    if (deleteError) {
      return res.status(500).json({ error: 'Error leaving group' });
    }

    const { data: remainingMembers } = await supabase
      .from('app_group_members')
      .select('teacher_id')
      .eq('group_id', groupId);

    if (remainingMembers && remainingMembers.length === 0) {
      await supabase
        .from('app_message_groups')
        .delete()
        .eq('id', groupId);
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Leave group error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/groups/:groupId', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const { groupId } = req.params;

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: authToken, error: authError } = await supabase
      .from('app_auth_tokens')
      .select('teacher_id')
      .eq('token', token)
      .maybeSingle();

    if (authError || !authToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    await supabase
      .from('app_group_members')
      .delete()
      .eq('group_id', groupId);

    await supabase
      .from('app_message_groups')
      .delete()
      .eq('id', groupId);

    res.json({ success: true });
  } catch (error) {
    console.error('Delete group error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});