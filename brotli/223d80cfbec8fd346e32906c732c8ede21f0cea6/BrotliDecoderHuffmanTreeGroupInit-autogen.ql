/**
 * @name brotli-223d80cfbec8fd346e32906c732c8ede21f0cea6-BrotliDecoderHuffmanTreeGroupInit
 * @id cpp/brotli/223d80cfbec8fd346e32906c732c8ede21f0cea6/BrotliDecoderHuffmanTreeGroupInit
 * @description brotli-223d80cfbec8fd346e32906c732c8ede21f0cea6-c/dec/state.c-BrotliDecoderHuffmanTreeGroupInit CVE-2020-8927
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter valphabet_size_limit_138, Literal target_0) {
		target_0.getValue()="31"
		and not target_0.getValue()="376"
		and target_0.getParent().(AddExpr).getParent().(RShiftExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=valphabet_size_limit_138
}

predicate func_1(Parameter valphabet_size_limit_138, Variable vkMaxHuffmanTableSize, ArrayExpr target_1) {
		target_1.getArrayBase().(VariableAccess).getTarget()=vkMaxHuffmanTableSize
		and target_1.getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=valphabet_size_limit_138
		and target_1.getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_1.getArrayOffset().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="5"
}

from Function func, Parameter valphabet_size_limit_138, Variable vkMaxHuffmanTableSize, Literal target_0, ArrayExpr target_1
where
func_0(valphabet_size_limit_138, target_0)
and func_1(valphabet_size_limit_138, vkMaxHuffmanTableSize, target_1)
and valphabet_size_limit_138.getType().hasName("uint32_t")
and vkMaxHuffmanTableSize.getType() instanceof ArrayType
and valphabet_size_limit_138.getParentScope+() = func
and not vkMaxHuffmanTableSize.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
