# agents/qa_agent.py

from langchain.chains import RetrievalQA
from langchain_community.chat_models import AzureChatOpenAI

vectorstore = None  # global placeholder for vectorstore
config = None       # global placeholder for config list

def set_vectorstore(vs):
    global vectorstore
    vectorstore = vs

def set_config(cfg):
    global config
    config = cfg

def answer_question_from_db(user_message: str) -> str:
    """
    Answers a user's question by searching the vector database for relevant documents.
    :param user_message: The question to answer.
    """
    try:
        if vectorstore is None or config is None:
            return "Error: vectorstore or config is not set."

        llm = AzureChatOpenAI(
            azure_endpoint=config[0]['base_url'],
            openai_api_version=config[0]['api_version'],
            deployment_name=config[0]['model'],
            openai_api_key=config[0]['openai_api_key']
        )

        qa_chain = RetrievalQA.from_chain_type(
            llm=llm, 
            chain_type="stuff", 
            retriever=vectorstore.as_retriever()
        )

        response = qa_chain.run(user_message)
        return response
    except Exception as e:
        return f"Error during QA retrieval: {str(e)}"
