/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-Member_actions_handler__trigger_actions
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/memberactionshandlertriggeractions
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/plugin_handlers/member_actions_handler.cc-Member_actions_handler__trigger_actions mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
	target_0.getExpr() instanceof NewExpr
	and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_2(Function func) {
exists(NewExpr target_2 |
	exists(FunctionCall obj_0 | obj_0=target_2.getAllocatorCall() |
		obj_0.getTarget().hasName("operator new")
		and obj_0.getArgument(0).(ErrorExpr).getType() instanceof LongType
	)
	and exists(ConstructorCall obj_1 | obj_1=target_2.getInitializer() |
		obj_1.getArgument(0).(ThisExpr).getType() instanceof PointerType
		and obj_1.getArgument(1) instanceof NewExpr
	)
	and target_2.getEnclosingFunction() = func
)
}

predicate func_4(Function func) {
exists(ExprStmt target_4 |
	target_4.getExpr().(DeleteExpr).getDeallocatorCall().(FunctionCall).getTarget().hasName("operator delete")
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
	and target_4.getFollowingStmt() instanceof ReturnStmt
)
}

predicate func_5(Parameter vevent_292, NewExpr target_5) {
	exists(FunctionCall obj_0 | obj_0=target_5.getAllocatorCall() |
		obj_0.getTarget().hasName("operator new")
		and obj_0.getArgument(0).(ErrorExpr).getType() instanceof LongType
	)
	and target_5.getInitializer().(ConstructorCall).getArgument(0).(VariableAccess).getTarget()=vevent_292
}

predicate func_7(Variable vparameters_296, VariableAccess target_7) {
	exists(FunctionCall obj_0 | obj_0=target_7.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().getName()="m_mysql_thread"
					and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
				and obj_2.getTarget().hasName("trigger")
			)
		)
	)
	and target_7.getTarget()=vparameters_296
}

from Function func, Variable vparameters_296, Parameter vevent_292, Initializer target_0, NewExpr target_5, VariableAccess target_7
where
func_0(func, target_0)
and not func_2(func)
and not func_4(func)
and func_5(vevent_292, target_5)
and func_7(vparameters_296, target_7)
and vparameters_296.getType().hasName("Member_actions_trigger_parameters *")
and vevent_292.getType().hasName("enum_action_event")
and vparameters_296.(LocalVariable).getFunction() = func
and vevent_292.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
