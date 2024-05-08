/**
 * @name mysql-server-5ccf484a4fc7b1de5fc41696bcd52c89544cf5d2-lock_wait_suspend_thread
 * @id cpp/mysql-server/5ccf484a4fc7b1de5fc41696bcd52c89544cf5d2/lockwaitsuspendthread
 * @description mysql-server-5ccf484a4fc7b1de5fc41696bcd52c89544cf5d2-storage/innobase/lock/lock0wait.cc-lock_wait_suspend_thread mysql-#33856332
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtrx_206, BlockStmt target_9, ExprStmt target_8) {
exists(EqualityOperation target_0 |
	exists(PointerFieldAccess obj_0 | obj_0=target_0.getLeftOperand() |
		obj_0.getTarget().getName()="error_state"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vtrx_206
	)
	and target_0.getRightOperand() instanceof EnumConstantAccess
	and target_0.getParent().(IfStmt).getThen()=target_9
	and target_0.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
)
}

predicate func_1(Variable vtrx_206, PointerFieldAccess target_1) {
	target_1.getTarget().getName()="error_state"
	and target_1.getQualifier().(VariableAccess).getTarget()=vtrx_206
	and target_1.getParent().(AssignExpr).getLValue() = target_1
}

predicate func_2(Variable vdiff_time_331, Variable vlock_sys, BlockStmt target_10, FunctionCall target_2) {
	exists(PointerFieldAccess obj_0 | obj_0=target_2.getArgument(1) |
		obj_0.getTarget().getName()="n_lock_max_wait_time"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vlock_sys
	)
	and exists(LogicalAndExpr obj_1 | obj_1=target_2.getParent() |
		obj_1.getRightOperand() instanceof FunctionCall
		and obj_1.getParent().(IfStmt).getThen()=target_10
	)
	and target_2.getTarget().hasName("operator>")
	and target_2.getArgument(0).(VariableAccess).getTarget()=vdiff_time_331
}

predicate func_3(Variable vtrx_206, VariableAccess target_3) {
	target_3.getTarget()=vtrx_206
	and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_5(Function func, DeclStmt target_5) {
	func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vstart_time_207, BlockStmt target_10, LogicalAndExpr target_6) {
	exists(FunctionCall obj_0 | obj_0=target_6.getRightOperand() |
		obj_0.getTarget().hasName("operator!=")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vstart_time_207
		and obj_0.getArgument(1).(ConstructorCall).getType() instanceof VoidType
	)
	and target_6.getLeftOperand() instanceof FunctionCall
	and target_6.getParent().(IfStmt).getThen()=target_10
}

predicate func_7(Variable vtrx_206, Variable vlock_wait_timeout_219, Variable vwait_time_324, BlockStmt target_9, LogicalAndExpr target_7) {
	exists(LogicalAndExpr obj_0 | obj_0=target_7.getLeftOperand() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getLeftOperand() |
			obj_1.getTarget().hasName("operator<")
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vlock_wait_timeout_219
			and obj_1.getArgument(1).(ConstructorCall).getArgument(0).(Literal).getValue()="100000000"
		)
		and exists(FunctionCall obj_2 | obj_2=obj_0.getRightOperand() |
			obj_2.getTarget().hasName("operator>")
			and obj_2.getArgument(0).(VariableAccess).getTarget()=vwait_time_324
			and obj_2.getArgument(1).(VariableAccess).getTarget()=vlock_wait_timeout_219
		)
	)
	and exists(NotExpr obj_3 | obj_3=target_7.getRightOperand() |
		exists(FunctionCall obj_4 | obj_4=obj_3.getOperand() |
			obj_4.getTarget().hasName("trx_is_high_priority")
			and obj_4.getArgument(0).(VariableAccess).getTarget()=vtrx_206
		)
	)
	and target_7.getParent().(IfStmt).getThen()=target_9
}

predicate func_8(Variable vtrx_206, LogicalAndExpr target_7, ExprStmt target_8) {
	exists(AssignExpr obj_0 | obj_0=target_8.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="error_state"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vtrx_206
		)
		and obj_0.getRValue() instanceof EnumConstantAccess
	)
	and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
}

predicate func_9(Function func, BlockStmt target_9) {
	exists(ExprStmt obj_0 | obj_0=target_9.getStmt(1) |
		exists(FunctionCall obj_1 | obj_1=obj_0.getExpr() |
			obj_1.getTarget().hasName("monitor_inc_value")
			and obj_1.getArgument(1).(Literal).getValue()="1"
		)
	)
	and target_9.getStmt(0) instanceof ExprStmt
	and target_9.getEnclosingFunction() = func
}

predicate func_10(Variable vdiff_time_331, Variable vlock_sys, BlockStmt target_10) {
	exists(ExprStmt obj_0 | obj_0=target_10.getStmt(0) |
		exists(AssignExpr obj_1 | obj_1=obj_0.getExpr() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getLValue() |
				obj_2.getTarget().getName()="n_lock_max_wait_time"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vlock_sys
			)
			and obj_1.getRValue().(VariableAccess).getTarget()=vdiff_time_331
		)
	)
}

from Function func, Variable vtrx_206, Variable vstart_time_207, Variable vlock_wait_timeout_219, Variable vwait_time_324, Variable vdiff_time_331, Variable vlock_sys, PointerFieldAccess target_1, FunctionCall target_2, VariableAccess target_3, DeclStmt target_5, LogicalAndExpr target_6, LogicalAndExpr target_7, ExprStmt target_8, BlockStmt target_9, BlockStmt target_10
where
not func_0(vtrx_206, target_9, target_8)
and func_1(vtrx_206, target_1)
and func_2(vdiff_time_331, vlock_sys, target_10, target_2)
and func_3(vtrx_206, target_3)
and func_5(func, target_5)
and func_6(vstart_time_207, target_10, target_6)
and func_7(vtrx_206, vlock_wait_timeout_219, vwait_time_324, target_9, target_7)
and func_8(vtrx_206, target_7, target_8)
and func_9(func, target_9)
and func_10(vdiff_time_331, vlock_sys, target_10)
and vtrx_206.getType().hasName("trx_t *")
and vstart_time_207.getType().hasName("time_point")
and vlock_wait_timeout_219.getType().hasName("const seconds")
and vwait_time_324.getType().hasName("const type")
and vdiff_time_331.getType().hasName("const type")
and vlock_sys.getType().hasName("lock_sys_t *")
and vtrx_206.(LocalVariable).getFunction() = func
and vstart_time_207.(LocalVariable).getFunction() = func
and vlock_wait_timeout_219.(LocalVariable).getFunction() = func
and vwait_time_324.(LocalVariable).getFunction() = func
and vdiff_time_331.(LocalVariable).getFunction() = func
and not vlock_sys.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
