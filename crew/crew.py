from crewai import Agent, Crew, Task, Process, LLM
from crewai.tools import tool
from langchain_community.tools import DuckDuckGoSearchResults
from dotenv import load_dotenv
import os

load_dotenv()

class SecurityCrew:
    def __init__(self):
        self.OpenAI = LLM(
            model="gpt-4o-mini",
            temperature=0.1,
            top_p=0.9,
            frequency_penalty=0.1,
            presence_penalty=0.1,
            stop=["END"],
            seed=42
        )

        self.security_researcher = Agent(
            role='Security Researcher',
            goal='Find the latest security vulnerabilities and exploits in the target systems.',
            backstory='An expert in cybersecurity with a focus on vulnerability assessment.',
            verbose=False,
            allow_delegation=False,
            tools=[self.search_tool],
            max_iter=3,
            llm=self.OpenAI
        )

        self.security_analyst = Agent(
            role='Security Analyst',
            goal='Analyze the collected data and report any data leak issues.',
            backstory='A skilled analyst with a keen eye for security threats.',
            verbose=False,
            allow_delegation=False,
            max_iter=10,
            llm=self.OpenAI,
            callback=self.post_action
        )

        self.searching_tasks = []

        self.analyze_leaks = Task(
            description='Analyze the collected data and report any data leak issues.',
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
    def prepare_inputs(inputs):
        # Read URLs from the file
        with open('data/urls_to_monitor.txt', 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
        inputs['urls_to_monitor'] = urls
        return inputs

    @staticmethod
    def process_output(output):
        # Modify output after the crew finishes
        output.raw += "\nProcessed after kickoff."
        print("Terminei de rodar tudo!")
        return output

    @staticmethod
    @tool("DuckDuckGo Search Tool")
    def search_tool(query: str) -> str:
        """Search the web for a given query."""
        duckduckgo_tool = DuckDuckGoSearchResults()
        response = duckduckgo_tool.invoke(query)
        return response

    @staticmethod
    def post_action():
        # Actions after the process ends
        print("Terminei de rodar tudo!")

    def run(self, inputs):
        urls_to_monitor = inputs['urls_to_monitor']

        for url in urls_to_monitor:
            self.searching_tasks.append(
                Task(
                description='Search if any information was pwned from each of these applications: , during the last 30 days, considering today as {date}.',
                expected_output=f'Informations of client data compromised from {url} in the last 30 days, giving details about the data compromised, the date of the leak, the type of data compromised, the number of clients affected, and the source of the leak.',
                agent=self.security_researcher
                )
            )

        self.searching_tasks.append(self.analyze_leaks)

        self.security_crew = Crew(
            agents=[self.security_researcher, self.security_analyst],
            tasks=self.searching_tasks,
            process=Process.sequential,
            verbose=True,
        )


        return self.security_crew.kickoff(inputs=inputs)
