import { createClient } from '@supabase/supabase-js';

// Substitua com os dados do seu projeto Supabase
const SUPABASE_URL = 'https://prjonmjbrpxxoeqqegoa.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByam9ubWpicnB4eG9lcXFlZ29hIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDMxNjExMTYsImV4cCI6MjA1ODczNzExNn0.Y5GjGVy7GK1-UnH4slWVSHatEoTEo6n4M1ZSrUs8VxQ';

// Criando a instância do Supabase
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

export default supabase;
