/**
 * @name libtiff-1b5e3b6a23827c33acf19ad50ce5ce78f12b3773-TIFFReadRawTile
 * @id cpp/libtiff/1b5e3b6a23827c33acf19ad50ce5ce78f12b3773/TIFFReadRawTile
 * @description libtiff-1b5e3b6a23827c33acf19ad50ce5ce78f12b3773-libtiff/tif_read.c-TIFFReadRawTile CVE-2019-14973
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmodule_1162, Variable vbytecount64_1164, Variable vbytecountm_1165, Parameter vtif_1160, ExprStmt target_8, FunctionCall target_9, ExprStmt target_10, EqualityOperation target_6, ExprStmt target_11) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("_TIFFCastUInt64ToSSize")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtif_1160
		and target_0.getArgument(1).(VariableAccess).getTarget()=vbytecount64_1164
		and target_0.getArgument(2).(VariableAccess).getTarget()=vmodule_1162
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytecountm_1165
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getArgument(2).(VariableAccess).getLocation())
		and target_0.getArgument(2).(VariableAccess).getLocation().isBefore(target_9.getArgument(4).(VariableAccess).getLocation())
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_0.getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vbytecountm_1165, BlockStmt target_12, ExprStmt target_13, FunctionCall target_9) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vbytecountm_1165
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_12
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getArgument(3).(VariableAccess).getLocation()))
}

predicate func_2(Variable vbytecount64_1164, Variable vbytecountm_1165, BlockStmt target_12, VariableAccess target_2) {
		target_2.getTarget()=vbytecountm_1165
		and target_2.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vbytecount64_1164
		and target_2.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_12
}

predicate func_3(Variable vbytecount64_1164, Variable vbytecountm_1165, VariableAccess target_3) {
		target_3.getTarget()=vbytecount64_1164
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytecountm_1165
}

predicate func_4(Parameter vtif_1160, VariableAccess target_4) {
		target_4.getTarget()=vtif_1160
		and target_4.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Variable vmodule_1162, VariableAccess target_5) {
		target_5.getTarget()=vmodule_1162
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Variable vbytecount64_1164, Variable vbytecountm_1165, BlockStmt target_12, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vbytecountm_1165
		and target_6.getAnOperand().(VariableAccess).getTarget()=vbytecount64_1164
		and target_6.getParent().(IfStmt).getThen()=target_12
}

predicate func_7(Variable vmodule_1162, Parameter vtif_1160, EqualityOperation target_6, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1160
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1162
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Integer overflow"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_8(Variable vmodule_1162, Parameter vtif_1160, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1160
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1162
		and target_8.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Compression scheme does not support access to raw uncompressed data"
}

predicate func_9(Variable vmodule_1162, Variable vbytecountm_1165, Parameter vtif_1160, FunctionCall target_9) {
		target_9.getTarget().hasName("TIFFReadRawTile1")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vtif_1160
		and target_9.getArgument(1).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_9.getArgument(2).(VariableAccess).getTarget().getType().hasName("void *")
		and target_9.getArgument(3).(VariableAccess).getTarget()=vbytecountm_1165
		and target_9.getArgument(4).(VariableAccess).getTarget()=vmodule_1162
}

predicate func_10(Variable vbytecount64_1164, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytecount64_1164
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
}

predicate func_11(Variable vbytecount64_1164, Parameter vtif_1160, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytecount64_1164
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFGetStrileByteCount")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_1160
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_12(BlockStmt target_12) {
		target_12.getStmt(0) instanceof ExprStmt
		and target_12.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_13(Variable vbytecount64_1164, Variable vbytecountm_1165, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytecountm_1165
		and target_13.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbytecount64_1164
}

from Function func, Variable vmodule_1162, Variable vbytecount64_1164, Variable vbytecountm_1165, Parameter vtif_1160, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, EqualityOperation target_6, ExprStmt target_7, ExprStmt target_8, FunctionCall target_9, ExprStmt target_10, ExprStmt target_11, BlockStmt target_12, ExprStmt target_13
where
not func_0(vmodule_1162, vbytecount64_1164, vbytecountm_1165, vtif_1160, target_8, target_9, target_10, target_6, target_11)
and not func_1(vbytecountm_1165, target_12, target_13, target_9)
and func_2(vbytecount64_1164, vbytecountm_1165, target_12, target_2)
and func_3(vbytecount64_1164, vbytecountm_1165, target_3)
and func_4(vtif_1160, target_4)
and func_5(vmodule_1162, target_5)
and func_6(vbytecount64_1164, vbytecountm_1165, target_12, target_6)
and func_7(vmodule_1162, vtif_1160, target_6, target_7)
and func_8(vmodule_1162, vtif_1160, target_8)
and func_9(vmodule_1162, vbytecountm_1165, vtif_1160, target_9)
and func_10(vbytecount64_1164, target_10)
and func_11(vbytecount64_1164, vtif_1160, target_11)
and func_12(target_12)
and func_13(vbytecount64_1164, vbytecountm_1165, target_13)
and vmodule_1162.getType().hasName("const char[]")
and vbytecount64_1164.getType().hasName("uint64")
and vbytecountm_1165.getType().hasName("tmsize_t")
and vtif_1160.getType().hasName("TIFF *")
and vmodule_1162.(LocalVariable).getFunction() = func
and vbytecount64_1164.(LocalVariable).getFunction() = func
and vbytecountm_1165.(LocalVariable).getFunction() = func
and vtif_1160.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
