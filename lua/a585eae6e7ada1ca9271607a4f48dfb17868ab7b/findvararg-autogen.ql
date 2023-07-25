/**
 * @name lua-a585eae6e7ada1ca9271607a4f48dfb17868ab7b-findvararg
 * @id cpp/lua/a585eae6e7ada1ca9271607a4f48dfb17868ab7b/findvararg
 * @description lua-a585eae6e7ada1ca9271607a4f48dfb17868ab7b-ldebug.c-findvararg CVE-2020-24370
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vn_188, Variable vnextra_190, BlockStmt target_9) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vn_188
		and target_0.getLesserOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vnextra_190
		and target_0.getParent().(IfStmt).getThen()=target_9)
}

predicate func_1(Parameter vn_188, RelationalOperation target_7) {
	exists(PointerArithmeticOperation target_1 |
		target_1.getLeftOperand() instanceof PointerArithmeticOperation
		and target_1.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_188
		and target_1.getRightOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StkId *")
		and target_7.getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vci_188, Variable vnextra_190, PointerArithmeticOperation target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="func"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_188
		and target_2.getRightOperand().(VariableAccess).getTarget()=vnextra_190
}

predicate func_3(Parameter vn_188, VariableAccess target_3) {
		target_3.getTarget()=vn_188
}

predicate func_5(Parameter vn_188, Variable vnextra_190, BlockStmt target_9, VariableAccess target_5) {
		target_5.getTarget()=vn_188
		and target_5.getParent().(LEExpr).getGreaterOperand().(VariableAccess).getTarget()=vnextra_190
		and target_5.getParent().(LEExpr).getParent().(IfStmt).getThen()=target_9
}

/*predicate func_6(Parameter vn_188, Variable vnextra_190, BlockStmt target_9, VariableAccess target_6) {
		target_6.getTarget()=vnextra_190
		and target_6.getParent().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vn_188
		and target_6.getParent().(LEExpr).getParent().(IfStmt).getThen()=target_9
}

*/
predicate func_7(Parameter vn_188, Variable vnextra_190, BlockStmt target_9, RelationalOperation target_7) {
		 (target_7 instanceof GEExpr or target_7 instanceof LEExpr)
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vn_188
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vnextra_190
		and target_7.getParent().(IfStmt).getThen()=target_9
}

predicate func_8(Parameter vn_188, PointerArithmeticOperation target_8) {
		target_8.getAnOperand() instanceof PointerArithmeticOperation
		and target_8.getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vn_188
		and target_8.getAnOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StkId *")
}

predicate func_9(BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StkId *")
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof PointerArithmeticOperation
		and target_9.getStmt(1).(ReturnStmt).getExpr().(StringLiteral).getValue()="(vararg)"
}

from Function func, Parameter vci_188, Parameter vn_188, Variable vnextra_190, PointerArithmeticOperation target_2, VariableAccess target_3, VariableAccess target_5, RelationalOperation target_7, PointerArithmeticOperation target_8, BlockStmt target_9
where
not func_0(vn_188, vnextra_190, target_9)
and not func_1(vn_188, target_7)
and func_2(vci_188, vnextra_190, target_2)
and func_3(vn_188, target_3)
and func_5(vn_188, vnextra_190, target_9, target_5)
and func_7(vn_188, vnextra_190, target_9, target_7)
and func_8(vn_188, target_8)
and func_9(target_9)
and vci_188.getType().hasName("CallInfo *")
and vn_188.getType().hasName("int")
and vnextra_190.getType().hasName("int")
and vci_188.getFunction() = func
and vn_188.getFunction() = func
and vnextra_190.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
