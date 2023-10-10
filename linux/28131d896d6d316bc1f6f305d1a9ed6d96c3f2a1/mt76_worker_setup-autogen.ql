/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt76_worker_setup
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt76-worker-setup
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt76_worker_setup CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vw_64) {
	exists(StmtExpr target_0 |
		target_0.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof FunctionCall
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("task_struct *")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("wake_up_process")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("task_struct *")
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableAccess).getType().hasName("task_struct *")
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="task"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vw_64)
}

predicate func_5(Parameter vw_64, Variable vret_69, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_5.getCondition().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_69
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PTR_ERR")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="task"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vw_64
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_69
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_5))
}

predicate func_8(Parameter vw_64, Parameter vname_66, Variable vdev_name_68) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("kthread_create_on_node")
		and target_8.getArgument(1).(VariableAccess).getTarget()=vw_64
		and target_8.getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_8.getArgument(2).(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_8.getArgument(3).(StringLiteral).getValue()="mt76-%s %s"
		and target_8.getArgument(4).(VariableAccess).getTarget()=vname_66
		and target_8.getArgument(5).(VariableAccess).getTarget()=vdev_name_68)
}

predicate func_9(Parameter vw_64) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="task"
		and target_9.getQualifier().(VariableAccess).getTarget()=vw_64
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall)
}

predicate func_11(Function func) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("PTR_ERR_OR_ZERO")
		and target_11.getArgument(0) instanceof PointerFieldAccess
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Parameter vw_64, Variable vret_69) {
	exists(VariableAccess target_12 |
		target_12.getTarget()=vret_69
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="task"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vw_64
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_69)
}

from Function func, Parameter vw_64, Parameter vname_66, Variable vdev_name_68, Variable vret_69
where
not func_0(vw_64)
and not func_5(vw_64, vret_69, func)
and func_8(vw_64, vname_66, vdev_name_68)
and func_9(vw_64)
and func_11(func)
and func_12(vw_64, vret_69)
and vw_64.getType().hasName("mt76_worker *")
and vname_66.getType().hasName("const char *")
and vdev_name_68.getType().hasName("const char *")
and vret_69.getType().hasName("int")
and vw_64.getParentScope+() = func
and vname_66.getParentScope+() = func
and vdev_name_68.getParentScope+() = func
and vret_69.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
