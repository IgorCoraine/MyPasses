from crewai import Agent, Crew, Task, Process, LLM
from crewai.tools import tool
from langchain_community.tools import DuckDuckGoSearchResults, DuckDuckGoSearchRun
import os, datetime

from dotenv import load_dotenv
load_dotenv()
  
OpenAI = LLM(
    model="gpt-4o-mini",
    temperature=0.1,
    max_tokens=150,
    top_p=0.9,
    frequency_penalty=0.1,
    presence_penalty=0.1,
    stop=["END"],
    seed=42
)

def prepare_inputs(self, inputs):
  # Read URLs from the file
  with open('data/urls_to_monitor.txt', 'r') as file:
      urls = [line.strip() for line in file if line.strip()]
  inputs['urls_to_monitor'] = urls
  return inputs

def process_output(self, output):
  # Modify output after the crew finishes
  output.raw += "\nProcessed after kickoff."
  print("Terminei de rodar tudo!")
  return output

@tool("DuckDuckGo Search Tool")
def search_tool(query: str) -> str:
  """Search the web for a given query."""
  duckduckgo_tool = DuckDuckGoSearchResults()
  response = duckduckgo_tool.invoke(query)
  return response

def post_action():
  # salvar um arquivo
  # enviar_email(contexto)
  # enviar um email
  # atualizar um banco de dados
  # enviar uma mensagem de whats
  print("Terminei de rodar tudo!")

security_researcher = Agent(
    role='Security Researcher',
    goal='Find the latest security vulnerabilities and exploits in the target systems.',
    backstory='An expert in cybersecurity with a focus on vulnerability assessment.',
    verbose=False,
    allow_delegation=False,
    tools=[search_tool],
    max_iter=10,
    llm=OpenAI
)

security_analyst = Agent(
    role='Security Analyst',
    goal='Analyze the collected data and report any data leak issues.',
    backstory='A skilled analyst with a keen eye for security threats.',
    verbose=False,
    allow_delegation=False,
    max_iter=10,
    llm=OpenAI,
    callback=post_action
)

search_for_leaks = Task(
    description='Search if any ingormation was pwned from any of this applications: {urls_to_monitor}, during last 30 days, considering the today as {date}.',
    expected_output='A sublist from {urls_to_monitor}, with the applications that had clients data compromissed in the last 30 days, giving datails about the data compromissed, the date of the leak, the type of data compromissed, the number of clients affected, and the source of the leak.',
    agent=security_researcher
)

analyze_leaks = Task(
    description='Analyze the collected data and report any data leak issues.',
    expected_output='A report of any data leak issues found in the target systems in Brasilian potuguese.', 
    agent=security_analyst
)

security_crew = Crew(
    agents=[security_researcher, security_analyst],
    tasks=[search_for_leaks, analyze_leaks],
    process=Process.sequential,
    verbose=True,
)


# Define the inputs for the crew
inputs = {
    'urls_to_monitor': ['htpps://youtube.com', 'https://github.com', 'Doxbin (TOoDA)'], 
    'date': str(datetime.datetime.now())
    }


try:
  # Kickoff the crew
  result = security_crew.kickoff(inputs=inputs)

  print("Resultado Final", result)
except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")
          


def check_password_pwned(password):
    """Check if a password has been pwned using Have I Been Pwned API v3."""
    # Hash the password using SHA-1
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    # Query the HIBP API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    if response.status_code != 200:
        raise Exception("Error fetching data from HIBP API.")
    
    # Check if the hash suffix appears in the response
    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return f"Password found {count} times! Consider using a stronger password."
    
    return "Password is safe (not found in HIBP database)."