/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-terminate_plugin_modules
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/terminatepluginmodules
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/plugin.cc-terminate_plugin_modules mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmodules_to_terminate_1440, OverloadedArrayExpr target_1, Function func) {
exists(IfStmt target_0 |
	exists(FunctionCall obj_0 | obj_0=target_0.getCondition() |
		obj_0.getTarget().hasName("operator bool")
		and obj_0.getQualifier().(OverloadedArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmodules_to_terminate_1440
	)
	and exists(BlockStmt obj_1 | obj_1=target_0.getThen() |
		exists(IfStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(EqualityOperation obj_3 | obj_3=obj_2.getCondition() |
				obj_3.getLeftOperand().(Literal).getValue()="0"
				and obj_3.getRightOperand().(VariableAccess).getType().hasName("Mysql_thread *")
			)
			and exists(BlockStmt obj_4 | obj_4=obj_2.getThen() |
				exists(ExprStmt obj_5 | obj_5=obj_4.getStmt(0) |
					exists(FunctionCall obj_6 | obj_6=obj_5.getExpr() |
						obj_6.getTarget().hasName("terminate")
						and obj_6.getQualifier().(VariableAccess).getType().hasName("Mysql_thread *")
					)
				)
				and exists(ExprStmt obj_7 | obj_7=obj_4.getStmt(2) |
					exists(AssignExpr obj_8 | obj_8=obj_7.getExpr() |
						obj_8.getLValue().(VariableAccess).getType().hasName("Mysql_thread *")
						and obj_8.getRValue().(Literal).getValue()="0"
					)
				)
				and obj_4.getStmt(1).(ExprStmt).getExpr().(DeleteExpr).getDeallocatorCall().(FunctionCall).getTarget().hasName("operator delete")
			)
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getFollowingStmt() instanceof ReturnStmt
	and target_1.getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getCondition().(FunctionCall).getQualifier().(OverloadedArrayExpr).getArrayBase().(VariableAccess).getLocation())
)
}

predicate func_1(Parameter vmodules_to_terminate_1440, OverloadedArrayExpr target_1) {
	target_1.getArrayBase().(VariableAccess).getTarget()=vmodules_to_terminate_1440
}

from Function func, Parameter vmodules_to_terminate_1440, OverloadedArrayExpr target_1
where
not func_0(vmodules_to_terminate_1440, target_1, func)
and func_1(vmodules_to_terminate_1440, target_1)
and vmodules_to_terminate_1440.getType().hasName("mask")
and vmodules_to_terminate_1440.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
