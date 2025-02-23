"""Security Crew module for monitoring data leaks and security vulnerabilities."""

from crewai import Agent, Crew, Task, Process, LLM
from crewai.tools import tool
from langchain_community.tools import DuckDuckGoSearchResults
from dotenv import load_dotenv
import os

# Constants
MODEL_NAME = "gpt-4o-mini"
URLS_FILE = 'data/urls_to_monitor.txt'

class SecurityCrew:
    """Manages security analysis tasks using AI agents."""

    def __init__(self):
        self.OpenAI = self._setup_llm()
        self.security_researcher = self._create_researcher()
        self.security_analyst = self._create_analyst()
        self._analyze_leaks = self._create_analyze_leaks()
        self.searching_tasks = []

    def _setup_llm(self) -> LLM:
        """Initialize LLM with specific parameters."""
        load_dotenv()
        return LLM(
            model=MODEL_NAME,
            temperature=0.1,
            top_p=0.9,
            frequency_penalty=0.1,
            presence_penalty=0.1,
            stop=["END"],
            seed=42
        )
        
    def _create_researcher(self) -> Agent:
        """Create security researcher agent."""
        return Agent(
            role='Security Researcher',
            goal='Find the latest security vulnerabilities and exploits in the target systems.',
            backstory='An expert in cybersecurity with a focus on vulnerability assessment.',
            verbose=False,
            allow_delegation=False,
            tools=[self.search_tool],
            max_iter=3,
            llm=self.OpenAI
        )

    def _create_analyst(self) -> Agent:
        """Create security analyst agent."""
        return Agent(
            role='Security Analyst',
            goal='Analyze the collected data and report any data leak issues.',
            backstory='A skilled analyst with a keen eye for security threats.',
            verbose=False,
            allow_delegation=False,
            max_iter=10,
            llm=self.OpenAI,
            callback=self.post_action
        )

    def _create_analyze_leaks(self) -> Task:
        """Analyze data leaks and report issues."""
        return Task(description='Analyze the collected data and report any data leak issues.',
            expected_output="""A report of all data leak issues found by the researchers. If it does not find any data leak issues, it should not be listed in the report. The report must be in Brazilian Portuguese.
            The report should follow the following format for each issue:
            **VAZAMENTO DE DADOS**
            **Aplicativo:**  
            **Data do Vazamento:**
            **Dados Comprometidos:** 
            **Tipo de Dados Comprometidos:** 
            **Número de Clientes Afetados:**
            **Fonte do Vazamento:**
            **Considere trocar a senha e atualizar esse aplicativo**
            ---""",
            agent=self.security_analyst
        )

    @staticmethod
    def prepare_inputs(inputs: dict) -> dict:
        """Prepare input data for processing."""
        with open(URLS_FILE, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
        inputs['urls_to_monitor'] = urls
        return inputs

    @staticmethod
    @tool("DuckDuckGo Search Tool")
    def search_tool(query: str) -> str:
        """Execute web search using DuckDuckGo."""
        return DuckDuckGoSearchResults().invoke(query)

    @staticmethod
    def post_action() -> None:
        """Execute post-processing actions."""
        print("Processing completed successfully!")

    def run(self, inputs: dict) -> str:
        """Execute security analysis workflow."""
        urls_to_monitor = inputs['urls_to_monitor']

        # Create search tasks for each URL
        for url in urls_to_monitor:
            self.searching_tasks.append(
                Task(
                    description='Search if any information was pwned from each of these applications: , during the last 30 days, considering today as {date}.',
                    expected_output=f'Informations of client data compromised from {url} in the last 30 days, giving details about the data compromised, the date of the leak, the type of data compromised, the number of clients affected, and the source of the leak.',
                    agent=self.security_researcher
                )
            )

        # Add analysis task
        self.searching_tasks.append(self._analyze_leaks)

        # Configure and execute crew
        crew = Crew(
            agents=[self.security_researcher, self.security_analyst],
            tasks=self.searching_tasks,
            process=Process.sequential,
            verbose=False,
        )

        return crew.kickoff(inputs=inputs)

