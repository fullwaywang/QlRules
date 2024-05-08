/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-Member_actions_handler__run_
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/memberactionshandlerrun
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/plugin_handlers/primary_election_invocation_handler.cc-Member_actions_handler__run_ mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
							exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
								obj_6.getTarget().hasName("prio")
								and obj_6.getQualifier().(ConstructorCall).getType() instanceof VoidType
							)
							and obj_5.getTarget().hasName("errcode")
							and obj_5.getArgument(0).(Literal).getValue()="13731"
						)
						and obj_4.getTarget().hasName("subsys")
						and obj_4.getArgument(0).(StringLiteral).getValue()="Repl"
					)
					and obj_3.getTarget().hasName("component")
					and obj_3.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
				)
				and obj_2.getTarget().hasName("source_line")
			)
		)
	)
	and target_0.getValue()="331"
	and not target_0.getValue()="334"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
							exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
								obj_6.getTarget().hasName("prio")
								and obj_6.getQualifier().(ConstructorCall).getType() instanceof VoidType
							)
							and obj_5.getTarget().hasName("errcode")
							and obj_5.getArgument(0).(Literal).getValue()="13732"
						)
						and obj_4.getTarget().hasName("subsys")
						and obj_4.getArgument(0).(StringLiteral).getValue()="Repl"
					)
					and obj_3.getTarget().hasName("component")
					and obj_3.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
				)
				and obj_2.getTarget().hasName("source_line")
			)
		)
	)
	and target_1.getValue()="342"
	and not target_1.getValue()="345"
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
							exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
								obj_6.getTarget().hasName("prio")
								and obj_6.getQualifier().(ConstructorCall).getType() instanceof VoidType
							)
							and obj_5.getTarget().hasName("errcode")
							and obj_5.getArgument(0).(Literal).getValue()="13733"
						)
						and obj_4.getTarget().hasName("subsys")
						and obj_4.getArgument(0).(StringLiteral).getValue()="Repl"
					)
					and obj_3.getTarget().hasName("component")
					and obj_3.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
				)
				and obj_2.getTarget().hasName("source_line")
			)
		)
	)
	and target_2.getValue()="349"
	and not target_2.getValue()="352"
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, ExprStmt target_3) {
	target_3.getExpr().(DeleteExpr).getDeallocatorCall().(FunctionCall).getTarget().hasName("operator delete")
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

from Function func, Literal target_0, Literal target_1, Literal target_2, ExprStmt target_3
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
