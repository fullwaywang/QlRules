/**
 * @name linux-dcd46d897adb70d63e025f175a00a89797d31a43-bprm_stack_limits
 * @id cpp/linux/dcd46d897adb70d63e025f175a00a89797d31a43/bprm-stack-limits
 * @description linux-dcd46d897adb70d63e025f175a00a89797d31a43-bprm_stack_limits CVE-2021-4034
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbprm_473) {
	exists(BuiltInChooseExpr target_0 |
		target_0.getChild(0).(LogicalAndExpr).getValue()="0"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getValue()="1"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getValue()="0"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(SizeofExprOperator).getExprOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(SizeofExprOperator).getExprOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getValue()="0"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getValue()="0"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getCondition().(Literal).getValue()="8"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getElse().(Literal).getValue()="8"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getValue()="1"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getCondition().(Literal).getValue()="8"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(Literal).getValue()="1"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getElse().(Literal).getValue()="8"
		and target_0.getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_0.getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbprm_473
		and target_0.getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_0.getChild(1).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="argc"
		and target_0.getChild(1).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbprm_473
		and target_0.getChild(1).(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_0.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="argc"
		and target_0.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbprm_473
		and target_0.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="1"
		and target_0.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_0.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getThen().(VariableAccess).getType().hasName("int")
		and target_0.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getElse().(VariableAccess).getType().hasName("int"))
}

predicate func_4(Parameter vbprm_473) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="argc"
		and target_4.getQualifier().(VariableAccess).getTarget()=vbprm_473)
}

predicate func_5(Parameter vbprm_473) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="rlim_stack"
		and target_5.getQualifier().(VariableAccess).getTarget()=vbprm_473)
}

from Function func, Parameter vbprm_473
where
not func_0(vbprm_473)
and func_4(vbprm_473)
and vbprm_473.getType().hasName("linux_binprm *")
and func_5(vbprm_473)
and vbprm_473.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
