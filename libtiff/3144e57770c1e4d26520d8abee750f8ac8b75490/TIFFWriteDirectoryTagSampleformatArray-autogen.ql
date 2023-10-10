/**
 * @name libtiff-3144e57770c1e4d26520d8abee750f8ac8b75490-TIFFWriteDirectoryTagSampleformatArray
 * @id cpp/libtiff/3144e57770c1e4d26520d8abee750f8ac8b75490/TIFFWriteDirectoryTagSampleformatArray
 * @description libtiff-3144e57770c1e4d26520d8abee750f8ac8b75490-libtiff/tif_dirwrite.c-TIFFWriteDirectoryTagSampleformatArray CVE-2017-7597
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_947) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("TIFFClampDoubleToFloat")
		and target_0.getArgument(0) instanceof ArrayExpr
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_0.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947)
}

predicate func_1(Variable vi_947) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("TIFFClampDoubleToInt8")
		and target_1.getArgument(0) instanceof ArrayExpr
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_1.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947)
}

predicate func_2(Variable vi_947) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("TIFFClampDoubleToInt16")
		and target_2.getArgument(0) instanceof ArrayExpr
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_2.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947)
}

predicate func_3(Variable vi_947) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("TIFFClampDoubleToInt32")
		and target_3.getArgument(0) instanceof ArrayExpr
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947)
}

predicate func_4(Variable vi_947) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("TIFFClampDoubleToUInt8")
		and target_4.getArgument(0) instanceof ArrayExpr
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_4.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947)
}

predicate func_5(Variable vi_947) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("TIFFClampDoubleToUInt16")
		and target_5.getArgument(0) instanceof ArrayExpr
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_5.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947)
}

predicate func_6(Variable vi_947) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("TIFFClampDoubleToUInt32")
		and target_6.getArgument(0) instanceof ArrayExpr
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_6.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947)
}

predicate func_7(Parameter vvalue_943, Variable vi_947, ArrayExpr target_7) {
		target_7.getArrayBase().(VariableAccess).getTarget()=vvalue_943
		and target_7.getArrayOffset().(VariableAccess).getTarget()=vi_947
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_7.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947
}

predicate func_8(Parameter vvalue_943, Variable vi_947, ArrayExpr target_8) {
		target_8.getArrayBase().(VariableAccess).getTarget()=vvalue_943
		and target_8.getArrayOffset().(VariableAccess).getTarget()=vi_947
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_8.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947
}

predicate func_9(Parameter vvalue_943, Variable vi_947, ArrayExpr target_9) {
		target_9.getArrayBase().(VariableAccess).getTarget()=vvalue_943
		and target_9.getArrayOffset().(VariableAccess).getTarget()=vi_947
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_9.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947
}

predicate func_10(Parameter vvalue_943, Variable vi_947, ArrayExpr target_10) {
		target_10.getArrayBase().(VariableAccess).getTarget()=vvalue_943
		and target_10.getArrayOffset().(VariableAccess).getTarget()=vi_947
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_10.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947
}

predicate func_11(Parameter vvalue_943, Variable vi_947, ArrayExpr target_11) {
		target_11.getArrayBase().(VariableAccess).getTarget()=vvalue_943
		and target_11.getArrayOffset().(VariableAccess).getTarget()=vi_947
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_11.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947
}

predicate func_12(Parameter vvalue_943, Variable vi_947, ArrayExpr target_12) {
		target_12.getArrayBase().(VariableAccess).getTarget()=vvalue_943
		and target_12.getArrayOffset().(VariableAccess).getTarget()=vi_947
		and target_12.getParent().(AssignExpr).getRValue() = target_12
		and target_12.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_12.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947
}

predicate func_13(Parameter vvalue_943, Variable vi_947, ArrayExpr target_13) {
		target_13.getArrayBase().(VariableAccess).getTarget()=vvalue_943
		and target_13.getArrayOffset().(VariableAccess).getTarget()=vi_947
		and target_13.getParent().(AssignExpr).getRValue() = target_13
		and target_13.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("void *")
		and target_13.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_947
}

from Function func, Parameter vvalue_943, Variable vi_947, ArrayExpr target_7, ArrayExpr target_8, ArrayExpr target_9, ArrayExpr target_10, ArrayExpr target_11, ArrayExpr target_12, ArrayExpr target_13
where
not func_0(vi_947)
and not func_1(vi_947)
and not func_2(vi_947)
and not func_3(vi_947)
and not func_4(vi_947)
and not func_5(vi_947)
and not func_6(vi_947)
and func_7(vvalue_943, vi_947, target_7)
and func_8(vvalue_943, vi_947, target_8)
and func_9(vvalue_943, vi_947, target_9)
and func_10(vvalue_943, vi_947, target_10)
and func_11(vvalue_943, vi_947, target_11)
and func_12(vvalue_943, vi_947, target_12)
and func_13(vvalue_943, vi_947, target_13)
and vvalue_943.getType().hasName("double *")
and vi_947.getType().hasName("uint32")
and vvalue_943.getFunction() = func
and vi_947.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
