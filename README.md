1. Fill DB credentials in db_utils.py
2. Set GOOGLE_API_KEY env var or put into ai_core.py
   export GOOGLE_API_KEY="your_key_here"
3. Start mentor chatbot (for embedding into mentor portal)
   streamlit run mentor_chat.py --server.port 8501
   use iframe src http://your-server:8501
4. Start admin chatbot
   streamlit run admin_chat.py --server.port 8502
   use iframe src http://your-server:8502
