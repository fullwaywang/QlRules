/**
 * @name libexpat-eb0362808b4f9f1e2345a0cf203b8cc196d776d9-storeRawNames
 * @id cpp/libexpat/eb0362808b4f9f1e2345a0cf203b8cc196d776d9/storeRawNames
 * @description libexpat-eb0362808b4f9f1e2345a0cf203b8cc196d776d9-storeRawNames CVE-2022-25315
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Size_t
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getRValue() instanceof BitwiseAndExpr
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vnameLen_2565) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vnameLen_2565
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_3(Variable vbufSize_2564, Variable vnameLen_2565) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbufSize_2564
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnameLen_2565
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("size_t"))
}

predicate func_5(Variable vtag_2562) {
	exists(BitwiseAndExpr target_5 |
		target_5.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="rawNameLength"
		and target_5.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtag_2562
		and target_5.getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getValue()="0"
		and target_5.getRightOperand().(ComplementExpr).getValue()="18446744073709551615")
}

predicate func_7(Variable vbufSize_2564, Variable vnameLen_2565) {
	exists(AddExpr target_7 |
		target_7.getAnOperand().(VariableAccess).getTarget()=vnameLen_2565
		and target_7.getAnOperand() instanceof BitwiseAndExpr
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbufSize_2564)
}

from Function func, Variable vtag_2562, Variable vbufSize_2564, Variable vnameLen_2565
where
not func_0(func)
and not func_1(func)
and not func_2(vnameLen_2565)
and not func_3(vbufSize_2564, vnameLen_2565)
and func_5(vtag_2562)
and func_7(vbufSize_2564, vnameLen_2565)
and vtag_2562.getType().hasName("TAG *")
and vbufSize_2564.getType().hasName("int")
and vnameLen_2565.getType().hasName("int")
and vtag_2562.getParentScope+() = func
and vbufSize_2564.getParentScope+() = func
and vnameLen_2565.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
