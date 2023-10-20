/**
 * @name expat-eb0362808b4f9f1e2345a0cf203b8cc196d776d9-storeRawNames
 * @id cpp/expat/eb0362808b4f9f1e2345a0cf203b8cc196d776d9/storeRawNames
 * @description expat-eb0362808b4f9f1e2345a0cf203b8cc196d776d9-expat/lib/xmlparse.c-storeRawNames CVE-2022-25315
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("size_t")
		and target_0.getRValue() instanceof BitwiseAndExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vnameLen_2565, ExprStmt target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vnameLen_2565
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbufSize_2564, Variable vnameLen_2565, RelationalOperation target_9, PointerArithmeticOperation target_10) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbufSize_2564
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnameLen_2565
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(VariableAccess).getLocation())
		and target_10.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vbufSize_2564, Variable vnameLen_2565, PointerArithmeticOperation target_10) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vnameLen_2565
		and target_3.getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbufSize_2564
		and target_10.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vtag_2562, BitwiseAndExpr target_4) {
		target_4.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="rawNameLength"
		and target_4.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtag_2562
		and target_4.getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getValue()="0"
		and target_4.getRightOperand().(ComplementExpr).getValue()="18446744073709551615"
}

predicate func_5(Variable vnameLen_2565, VariableAccess target_5) {
		target_5.getTarget()=vnameLen_2565
}

predicate func_6(Variable vbufSize_2564, Variable vnameLen_2565, AddExpr target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vnameLen_2565
		and target_6.getAnOperand() instanceof BitwiseAndExpr
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbufSize_2564
}

predicate func_8(Variable vnameLen_2565, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vnameLen_2565
}

predicate func_9(Variable vtag_2562, Variable vbufSize_2564, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vbufSize_2564
		and target_9.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="bufEnd"
		and target_9.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtag_2562
		and target_9.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_9.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtag_2562
}

predicate func_10(Variable vtag_2562, Variable vnameLen_2565, PointerArithmeticOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtag_2562
		and target_10.getAnOperand().(VariableAccess).getTarget()=vnameLen_2565
}

from Function func, Variable vtag_2562, Variable vbufSize_2564, Variable vnameLen_2565, BitwiseAndExpr target_4, VariableAccess target_5, AddExpr target_6, ExprStmt target_8, RelationalOperation target_9, PointerArithmeticOperation target_10
where
not func_0(func)
and not func_1(vnameLen_2565, target_8)
and not func_2(vbufSize_2564, vnameLen_2565, target_9, target_10)
and func_4(vtag_2562, target_4)
and func_5(vnameLen_2565, target_5)
and func_6(vbufSize_2564, vnameLen_2565, target_6)
and func_8(vnameLen_2565, target_8)
and func_9(vtag_2562, vbufSize_2564, target_9)
and func_10(vtag_2562, vnameLen_2565, target_10)
and vtag_2562.getType().hasName("TAG *")
and vbufSize_2564.getType().hasName("int")
and vnameLen_2565.getType().hasName("int")
and vtag_2562.getParentScope+() = func
and vbufSize_2564.getParentScope+() = func
and vnameLen_2565.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
