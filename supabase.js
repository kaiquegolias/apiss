import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.SUPABASE_URL
const supabaseKey = process.env.SUPABASE_KEY

// Exportação nomeada (sem default)
export const supabase = createClient(supabaseUrl, supabaseKey)
