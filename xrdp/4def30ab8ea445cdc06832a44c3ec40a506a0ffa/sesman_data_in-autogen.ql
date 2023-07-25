/**
 * @name xrdp-4def30ab8ea445cdc06832a44c3ec40a506a0ffa-sesman_data_in
 * @id cpp/xrdp/4def30ab8ea445cdc06832a44c3ec40a506a0ffa/sesman-data-in
 * @description xrdp-4def30ab8ea445cdc06832a44c3ec40a506a0ffa-sesman/sesman.c-sesman_data_in CVE-2022-23613
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="sesman_data_in: bad message size"
		and not target_0.getValue()="sesman_data_in: bad message size %d"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vsize_280, BlockStmt target_4, ExprStmt target_5, RelationalOperation target_3) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_280
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_1.getAnOperand() instanceof RelationalOperation
		and target_1.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vself_277, Variable vsize_280, BlockStmt target_4, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vsize_280
		and target_3.getLesserOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vself_277
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("log_message")
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_4.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_5(Parameter vself_277, Variable vsize_280, ExprStmt target_5) {
		target_5.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vsize_280
		and target_5.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_5.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_5.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vself_277
}

from Function func, Parameter vself_277, Variable vsize_280, StringLiteral target_0, RelationalOperation target_3, BlockStmt target_4, ExprStmt target_5
where
func_0(func, target_0)
and not func_1(vsize_280, target_4, target_5, target_3)
and func_3(vself_277, vsize_280, target_4, target_3)
and func_4(target_4)
and func_5(vself_277, vsize_280, target_5)
and vself_277.getType().hasName("trans *")
and vsize_280.getType().hasName("int")
and vself_277.getParentScope+() = func
and vsize_280.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
