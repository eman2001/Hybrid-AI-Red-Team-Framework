import json


def format_security_context(
        attack_chain
):

    context = {
        "framework": attack_chain.get(
            "framework"
        ),

        "generated": attack_chain.get(
            "generated"
        ),

        "attack_phases": [],

        "techniques": []
    }


    chain = attack_chain.get(
        "attack_chain",
        {}
    )


    for phase in chain.values():

        context["attack_phases"].append(
            {
                "phase":
                    phase.get("phase_name"),

                "tactic":
                    phase.get("tactic"),

                "confidence":
                    phase.get("confidence"),

                "host":
                    phase.get("hosts", [])
            }
        )


        for tech in phase.get(
            "techniques",
            []
        ):

            context["techniques"].append(
                {
                    "id":
                        tech.get("id"),

                    "name":
                        tech.get("name")
                }
            )


    return context
