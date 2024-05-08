/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-initialize_plugin_modules
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/initializepluginmodules
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/plugin.cc-initialize_plugin_modules mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmodules_to_init_1294, IfStmt target_1, OverloadedArrayExpr target_2, Function func) {
exists(IfStmt target_0 |
	exists(FunctionCall obj_0 | obj_0=target_0.getCondition() |
		obj_0.getTarget().hasName("operator bool")
		and obj_0.getQualifier().(OverloadedArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmodules_to_init_1294
	)
	and exists(BlockStmt obj_1 | obj_1=target_0.getThen() |
		exists(ExprStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(AssignExpr obj_3 | obj_3=obj_2.getExpr() |
				exists(NewExpr obj_4 | obj_4=obj_3.getRValue() |
					exists(FunctionCall obj_5 | obj_5=obj_4.getAllocatorCall() |
						obj_5.getTarget().hasName("operator new")
						and obj_5.getArgument(0).(ErrorExpr).getType() instanceof LongType
					)
					and exists(ConstructorCall obj_6 | obj_6=obj_4.getInitializer() |
						obj_6.getArgument(0).(VariableAccess).getType().hasName("PSI_thread_key")
						and obj_6.getArgument(1).(VariableAccess).getType().hasName("PSI_mutex_key")
						and obj_6.getArgument(2).(VariableAccess).getType().hasName("PSI_cond_key")
						and obj_6.getArgument(3).(VariableAccess).getType().hasName("PSI_mutex_key")
						and obj_6.getArgument(4).(VariableAccess).getType().hasName("PSI_cond_key")
					)
				)
				and obj_3.getLValue().(VariableAccess).getType().hasName("Mysql_thread *")
			)
		)
		and exists(IfStmt obj_7 | obj_7=obj_1.getStmt(1) |
			exists(FunctionCall obj_8 | obj_8=obj_7.getCondition() |
				obj_8.getTarget().hasName("initialize")
				and obj_8.getQualifier().(VariableAccess).getType().hasName("Mysql_thread *")
			)
			and obj_7.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_1.getLocation())
	and target_0.getCondition().(FunctionCall).getQualifier().(OverloadedArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getArrayBase().(VariableAccess).getLocation())
)
}

predicate func_1(Parameter vmodules_to_init_1294, IfStmt target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getCondition() |
		obj_0.getTarget().hasName("operator bool")
		and obj_0.getQualifier().(OverloadedArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmodules_to_init_1294
	)
	and exists(BlockStmt obj_1 | obj_1=target_1.getThen() |
		exists(IfStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(AssignExpr obj_3 | obj_3=obj_2.getCondition() |
				obj_3.getLValue().(VariableAccess).getTarget().getType().hasName("int")
				and obj_3.getRValue().(FunctionCall).getTarget().hasName("initialize_registry_module")
			)
			and obj_2.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget().getType().hasName("int")
		)
	)
}

predicate func_2(Parameter vmodules_to_init_1294, OverloadedArrayExpr target_2) {
	target_2.getArrayBase().(VariableAccess).getTarget()=vmodules_to_init_1294
}

from Function func, Parameter vmodules_to_init_1294, IfStmt target_1, OverloadedArrayExpr target_2
where
not func_0(vmodules_to_init_1294, target_1, target_2, func)
and func_1(vmodules_to_init_1294, target_1)
and func_2(vmodules_to_init_1294, target_2)
and vmodules_to_init_1294.getType().hasName("mask")
and vmodules_to_init_1294.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
