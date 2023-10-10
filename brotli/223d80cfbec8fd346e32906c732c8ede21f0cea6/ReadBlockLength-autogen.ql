/**
 * @name brotli-223d80cfbec8fd346e32906c732c8ede21f0cea6-ReadBlockLength
 * @id cpp/brotli/223d80cfbec8fd346e32906c732c8ede21f0cea6/ReadBlockLength
 * @description brotli-223d80cfbec8fd346e32906c732c8ede21f0cea6-c/dec/decode.c-ReadBlockLength CVE-2020-8927
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcode_875, ExprStmt target_6, ArrayExpr target_5) {
	exists(ArrayExpr target_0 |
		target_0.getArrayBase().(VariableAccess).getType().hasName("const BrotliPrefixCodeRange[26]")
		and target_0.getArrayOffset().(VariableAccess).getTarget()=vcode_875
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArrayOffset().(VariableAccess).getLocation())
		and target_0.getArrayOffset().(VariableAccess).getLocation().isBefore(target_5.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcode_875, ArrayExpr target_4) {
	exists(ArrayExpr target_1 |
		target_1.getArrayBase().(VariableAccess).getType().hasName("const BrotliPrefixCodeRange[26]")
		and target_1.getArrayOffset().(VariableAccess).getTarget()=vcode_875
		and target_4.getArrayOffset().(VariableAccess).getLocation().isBefore(target_1.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_2(Variable vcode_875, Variable vkBlockLengthPrefixCode, VariableAccess target_2) {
		target_2.getTarget()=vcode_875
		and target_2.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkBlockLengthPrefixCode
}

predicate func_3(Variable vcode_875, Variable vkBlockLengthPrefixCode, VariableAccess target_3) {
		target_3.getTarget()=vcode_875
		and target_3.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkBlockLengthPrefixCode
}

predicate func_4(Variable vcode_875, Variable vkBlockLengthPrefixCode, ExprStmt target_6, ArrayExpr target_5, ArrayExpr target_4) {
		target_4.getArrayBase().(VariableAccess).getTarget()=vkBlockLengthPrefixCode
		and target_4.getArrayOffset().(VariableAccess).getTarget()=vcode_875
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getArrayOffset().(VariableAccess).getLocation())
		and target_4.getArrayOffset().(VariableAccess).getLocation().isBefore(target_5.getArrayOffset().(VariableAccess).getLocation())
}

predicate func_5(Variable vcode_875, Variable vkBlockLengthPrefixCode, ArrayExpr target_4, ArrayExpr target_5) {
		target_5.getArrayBase().(VariableAccess).getTarget()=vkBlockLengthPrefixCode
		and target_5.getArrayOffset().(VariableAccess).getTarget()=vcode_875
		and target_4.getArrayOffset().(VariableAccess).getLocation().isBefore(target_5.getArrayOffset().(VariableAccess).getLocation())
}

predicate func_6(Variable vcode_875, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_875
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadSymbol")
}

from Function func, Variable vcode_875, Variable vkBlockLengthPrefixCode, VariableAccess target_2, VariableAccess target_3, ArrayExpr target_4, ArrayExpr target_5, ExprStmt target_6
where
not func_0(vcode_875, target_6, target_5)
and not func_1(vcode_875, target_4)
and func_2(vcode_875, vkBlockLengthPrefixCode, target_2)
and func_3(vcode_875, vkBlockLengthPrefixCode, target_3)
and func_4(vcode_875, vkBlockLengthPrefixCode, target_6, target_5, target_4)
and func_5(vcode_875, vkBlockLengthPrefixCode, target_4, target_5)
and func_6(vcode_875, target_6)
and vcode_875.getType().hasName("uint32_t")
and vkBlockLengthPrefixCode.getType() instanceof ArrayType
and vcode_875.getParentScope+() = func
and not vkBlockLengthPrefixCode.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
