/**
 * @name linux-0b074ab7fc0d575247b9cc9f93bb7e007ca38840-line6_probe
 * @id cpp/linux/0b074ab7fc0d575247b9cc9f93bb7e007ca38840/line6-probe
 * @description linux-0b074ab7fc0d575247b9cc9f93bb7e007ca38840-line6_probe 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vline6_735) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="8584"
		and target_0.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline6_735)
}

predicate func_1(Variable vline6_735, Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Struct
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__init_work")
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="startup_work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6_735
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="startup_work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6_735
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ClassAggregateLiteral).getValue()="{...}"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lockdep_init_map")
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lockdep_map"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="startup_work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6_735
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="(work_completion)(&(&line6->startup_work)->work)"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("lock_class_key")
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("INIT_LIST_HEAD")
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="entry"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="startup_work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6_735
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="func"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="startup_work"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6_735
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Struct
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("init_timer_key")
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="timer"
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="startup_work"
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6_735
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2097152"
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="&(&line6->startup_work)->timer"
		and target_1.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("lock_class_key")
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_1))
}

predicate func_12(Variable vline6_735) {
	exists(PointerFieldAccess target_12 |
		target_12.getTarget().getName()="ifcdev"
		and target_12.getQualifier().(VariableAccess).getTarget()=vline6_735)
}

from Function func, Variable vline6_735
where
func_0(vline6_735)
and not func_1(vline6_735, func)
and vline6_735.getType().hasName("usb_line6 *")
and func_12(vline6_735)
and vline6_735.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
