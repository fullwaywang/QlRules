/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-attempt_rejoin_
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/attemptrejoin
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/plugin_handlers/member_actions_handler.cc-attempt_rejoin_ mysql-#33025231
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
							and obj_5.getArgument(0).(Literal).getValue()="11644"
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
	and target_0.getValue()="1701"
	and not target_0.getValue()="1730"
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
							and obj_5.getArgument(0).(Literal).getValue()="13659"
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
	and target_1.getValue()="1705"
	and not target_1.getValue()="1734"
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getParent() |
		exists(AssignExpr obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getRValue() |
				exists(AddressOfExpr obj_3 | obj_3=obj_2.getArgument(0) |
					exists(ValueFieldAccess obj_4 | obj_4=obj_3.getOperand() |
						obj_4.getTarget().getName()="plugin_modules_termination_mutex"
						and obj_4.getQualifier().(VariableAccess).getTarget().getType().hasName("plugin_local_variables")
					)
				)
				and obj_2.getTarget().hasName("inline_mysql_mutex_trylock")
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/plugin/group_replication/src/plugin.cc"
			)
		)
	)
	and target_2.getValue()="1721"
	and not target_2.getValue()="1750"
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(AddressOfExpr obj_3 | obj_3=obj_2.getArgument(0) |
					exists(ValueFieldAccess obj_4 | obj_4=obj_3.getOperand() |
						obj_4.getTarget().getName()="plugin_modules_termination_mutex"
						and obj_4.getQualifier().(VariableAccess).getTarget().getType().hasName("plugin_local_variables")
					)
				)
				and obj_2.getTarget().hasName("inline_mysql_mutex_unlock")
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/plugin/group_replication/src/plugin.cc"
			)
		)
	)
	and target_3.getValue()="1724"
	and not target_3.getValue()="1753"
	and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
	exists(FunctionCall obj_0 | obj_0=target_4.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11674"
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
	and target_4.getValue()="1741"
	and not target_4.getValue()="1770"
	and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, Literal target_5) {
	exists(FunctionCall obj_0 | obj_0=target_5.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11674"
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
	and target_5.getValue()="1747"
	and not target_5.getValue()="1776"
	and target_5.getEnclosingFunction() = func
}

predicate func_6(Function func, Literal target_6) {
	exists(FunctionCall obj_0 | obj_0=target_6.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="13374"
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
	and target_6.getValue()="1787"
	and not target_6.getValue()="1816"
	and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vmodules_mask_1669, ExprStmt target_8, ExprStmt target_9, Function func) {
exists(ExprStmt target_7 |
	exists(FunctionCall obj_0 | obj_0=target_7.getExpr() |
		obj_0.getTarget().hasName("set")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vmodules_mask_1669
		and obj_0.getArgument(1).(Literal).getValue()="1"
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
	and target_7.getLocation().isBefore(target_8.getLocation())
	and target_9.getExpr().(FunctionCall).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getQualifier().(VariableAccess).getLocation())
)
}

predicate func_8(Variable vmodules_mask_1669, ExprStmt target_8) {
	exists(FunctionCall obj_0 | obj_0=target_8.getExpr() |
		obj_0.getTarget().hasName("set")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vmodules_mask_1669
		and obj_0.getArgument(1).(Literal).getValue()="1"
	)
}

predicate func_9(Variable vmodules_mask_1669, ExprStmt target_9) {
	exists(FunctionCall obj_0 | obj_0=target_9.getExpr() |
		obj_0.getTarget().hasName("set")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vmodules_mask_1669
		and obj_0.getArgument(1).(Literal).getValue()="1"
	)
}

from Function func, Variable vmodules_mask_1669, Literal target_0, Literal target_1, Literal target_2, Literal target_3, Literal target_4, Literal target_5, Literal target_6, ExprStmt target_8, ExprStmt target_9
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and not func_7(vmodules_mask_1669, target_8, target_9, func)
and func_8(vmodules_mask_1669, target_8)
and func_9(vmodules_mask_1669, target_9)
and vmodules_mask_1669.getType().hasName("mask")
and vmodules_mask_1669.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
