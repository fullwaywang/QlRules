/**
 * @name mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-queue_event
 * @id cpp/mysql-server/70cf38f9528fc577905053dbe95782463baff9c7/queueevent
 * @description mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-sql/rpl_slave.cc-queue_event mysql-#32103192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vglobal_sid_lock, Variable vgtid_ev_8588, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3) {
exists(IfStmt target_0 |
	exists(NotExpr obj_0 | obj_0=target_0.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getOperand() |
			obj_1.getTarget().hasName("is_valid")
			and obj_1.getQualifier().(VariableAccess).getTarget()=vgtid_ev_8588
		)
	)
	and exists(BlockStmt obj_2 | obj_2=target_0.getThen() |
		exists(ExprStmt obj_3 | obj_3=obj_2.getStmt(0) |
			exists(FunctionCall obj_4 | obj_4=obj_3.getExpr() |
				obj_4.getTarget().hasName("unlock")
				and obj_4.getQualifier().(VariableAccess).getTarget()=vglobal_sid_lock
			)
		)
	)
	and target_0.getLocation().isBefore(target_1.getLocation())
	and target_2.getExpr().(FunctionCall).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getQualifier().(VariableAccess).getLocation())
	and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getQualifier().(VariableAccess).getLocation())
)
}

predicate func_1(Variable vgtid_ev_8588, ExprStmt target_1) {
	exists(AssignExpr obj_0 | obj_0=target_1.getExpr() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="sidno"
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("Gtid")
		)
		and exists(FunctionCall obj_2 | obj_2=obj_0.getRValue() |
			obj_2.getTarget().hasName("get_sidno")
			and obj_2.getQualifier().(VariableAccess).getTarget()=vgtid_ev_8588
			and obj_2.getArgument(0).(Literal).getValue()="0"
		)
	)
}

predicate func_2(Variable vglobal_sid_lock, EqualityOperation target_5, ExprStmt target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getExpr() |
		obj_0.getTarget().hasName("unlock")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vglobal_sid_lock
	)
	and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_3(Variable vglobal_sid_lock, ExprStmt target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getExpr() |
		obj_0.getTarget().hasName("unlock")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vglobal_sid_lock
	)
}

predicate func_5(Function func, EqualityOperation target_5) {
	target_5.getLeftOperand().(FunctionCall).getTarget().hasName("get_gtid_mode")
	and target_5.getEnclosingFunction() = func
}

from Function func, Variable vglobal_sid_lock, Variable vgtid_ev_8588, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_5
where
not func_0(vglobal_sid_lock, vgtid_ev_8588, target_1, target_2, target_3)
and func_1(vgtid_ev_8588, target_1)
and func_2(vglobal_sid_lock, target_5, target_2)
and func_3(vglobal_sid_lock, target_3)
and func_5(func, target_5)
and vglobal_sid_lock.getType().hasName("Checkable_rwlock *")
and vgtid_ev_8588.getType().hasName("Gtid_log_event")
and not vglobal_sid_lock.getParentScope+() = func
and vgtid_ev_8588.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
