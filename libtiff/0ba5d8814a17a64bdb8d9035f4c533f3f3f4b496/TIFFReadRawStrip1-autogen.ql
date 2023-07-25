/**
 * @name libtiff-0ba5d8814a17a64bdb8d9035f4c533f3f3f4b496-TIFFReadRawStrip1
 * @id cpp/libtiff/0ba5d8814a17a64bdb8d9035f4c533f3f3f4b496/TIFFReadRawStrip1
 * @description libtiff-0ba5d8814a17a64bdb8d9035f4c533f3f3f4b496-libtiff/tif_read.c-TIFFReadRawStrip1 CVE-2016-6223
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vma_420, ExprStmt target_3) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand() instanceof ArrayExpr
		and target_0.getLesserOperand().(BinaryBitwiseOperation).getValue()="9223372036854775807"
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vma_420
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="tif_size"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFF *")
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_3)
}

predicate func_1(Variable vtd_387, Parameter vstrip_384, ArrayExpr target_1) {
		target_1.getArrayBase().(PointerFieldAccess).getTarget().getName()="td_stripoffset"
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_387
		and target_1.getArrayOffset().(VariableAccess).getTarget()=vstrip_384
}

predicate func_2(Variable vma_420, ExprStmt target_3, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vma_420
		and target_2.getAnOperand() instanceof ArrayExpr
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vma_420
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="tif_size"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFF *")
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vtd_387, Variable vma_420, Parameter vstrip_384, ArrayExpr target_1, EqualityOperation target_2, ExprStmt target_3
where
not func_0(vma_420, target_3)
and func_1(vtd_387, vstrip_384, target_1)
and func_2(vma_420, target_3, target_2)
and func_3(target_3)
and vtd_387.getType().hasName("TIFFDirectory *")
and vma_420.getType().hasName("tmsize_t")
and vstrip_384.getType().hasName("uint32")
and vtd_387.(LocalVariable).getFunction() = func
and vma_420.(LocalVariable).getFunction() = func
and vstrip_384.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
