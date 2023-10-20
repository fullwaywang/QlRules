/**
 * @name libtiff-1b5e3b6a23827c33acf19ad50ce5ce78f12b3773-TIFFReadRawStrip
 * @id cpp/libtiff/1b5e3b6a23827c33acf19ad50ce5ce78f12b3773/TIFFReadRawStrip
 * @description libtiff-1b5e3b6a23827c33acf19ad50ce5ce78f12b3773-libtiff/tif_read.c-TIFFReadRawStrip CVE-2019-14973
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmodule_709, Variable vbytecount_711, Variable vbytecountm_712, Parameter vtif_707, ExprStmt target_14, ExprStmt target_12, ExprStmt target_15) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("_TIFFCastUInt64ToSSize")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtif_707
		and target_0.getArgument(1).(VariableAccess).getTarget()=vbytecount_711
		and target_0.getArgument(2).(VariableAccess).getTarget()=vmodule_709
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytecountm_712
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getArgument(2).(VariableAccess).getLocation())
		and target_0.getArgument(2).(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vbytecountm_712, BlockStmt target_17, ExprStmt target_9, LogicalAndExpr target_18) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vbytecountm_712
		and target_1.getAnOperand() instanceof Literal
		and target_1.getParent().(IfStmt).getThen()=target_17
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_18.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbytecount_711, Variable vbytecountm_712, BlockStmt target_17, VariableAccess target_2) {
		target_2.getTarget()=vbytecountm_712
		and target_2.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vbytecount_711
		and target_2.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_17
}

predicate func_3(Variable vbytecount_711, BlockStmt target_19, VariableAccess target_3) {
		target_3.getTarget()=vbytecount_711
		and target_3.getParent().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(LEExpr).getParent().(IfStmt).getThen()=target_19
}

predicate func_5(Parameter vtif_707, VariableAccess target_5) {
		target_5.getTarget()=vtif_707
		and target_5.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Variable vmodule_709, VariableAccess target_6) {
		target_6.getTarget()=vmodule_709
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_7(Parameter vstrip_707, Variable vmodule_709, Variable vbytecount_711, Parameter vtif_707, Function func, IfStmt target_7) {
		target_7.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbytecount_711
		and target_7.getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_707
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_709
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%llu: Invalid strip byte count, strip %lu"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbytecount_711
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vstrip_707
		and target_7.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

/*predicate func_8(Parameter vstrip_707, Variable vmodule_709, Variable vbytecount_711, Parameter vtif_707, FunctionCall target_8) {
		target_8.getTarget().hasName("TIFFErrorExt")
		and target_8.getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_707
		and target_8.getArgument(1).(VariableAccess).getTarget()=vmodule_709
		and target_8.getArgument(2).(StringLiteral).getValue()="%llu: Invalid strip byte count, strip %lu"
		and target_8.getArgument(3).(VariableAccess).getTarget()=vbytecount_711
		and target_8.getArgument(4).(VariableAccess).getTarget()=vstrip_707
}

*/
predicate func_9(Variable vbytecount_711, Variable vbytecountm_712, Function func, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytecountm_712
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbytecount_711
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

/*predicate func_10(Variable vbytecount_711, Variable vbytecountm_712, EqualityOperation target_11, VariableAccess target_10) {
		target_10.getTarget()=vbytecount_711
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytecountm_712
		and target_10.getLocation().isBefore(target_11.getAnOperand().(VariableAccess).getLocation())
}

*/
predicate func_11(Variable vbytecount_711, Variable vbytecountm_712, BlockStmt target_17, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vbytecountm_712
		and target_11.getAnOperand().(VariableAccess).getTarget()=vbytecount_711
		and target_11.getParent().(IfStmt).getThen()=target_17
}

predicate func_12(Variable vmodule_709, Parameter vtif_707, EqualityOperation target_11, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_707
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_709
		and target_12.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Integer overflow"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_13(EqualityOperation target_11, Function func, ReturnStmt target_13) {
		target_13.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_13.getEnclosingFunction() = func
}

predicate func_14(Variable vmodule_709, Parameter vtif_707, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_707
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_709
		and target_14.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Compression scheme does not support access to raw uncompressed data"
}

predicate func_15(Parameter vstrip_707, Variable vbytecount_711, Parameter vtif_707, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytecount_711
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFGetStrileByteCount")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_707
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstrip_707
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0) instanceof ExprStmt
		and target_17.getStmt(1) instanceof ReturnStmt
}

predicate func_18(Variable vbytecountm_712, LogicalAndExpr target_18) {
		target_18.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_18.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_18.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_18.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbytecountm_712
}

predicate func_19(BlockStmt target_19) {
		target_19.getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_19.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

from Function func, Parameter vstrip_707, Variable vmodule_709, Variable vbytecount_711, Variable vbytecountm_712, Parameter vtif_707, VariableAccess target_2, VariableAccess target_3, VariableAccess target_5, VariableAccess target_6, IfStmt target_7, ExprStmt target_9, EqualityOperation target_11, ExprStmt target_12, ReturnStmt target_13, ExprStmt target_14, ExprStmt target_15, BlockStmt target_17, LogicalAndExpr target_18, BlockStmt target_19
where
not func_0(vmodule_709, vbytecount_711, vbytecountm_712, vtif_707, target_14, target_12, target_15)
and not func_1(vbytecountm_712, target_17, target_9, target_18)
and func_2(vbytecount_711, vbytecountm_712, target_17, target_2)
and func_3(vbytecount_711, target_19, target_3)
and func_5(vtif_707, target_5)
and func_6(vmodule_709, target_6)
and func_7(vstrip_707, vmodule_709, vbytecount_711, vtif_707, func, target_7)
and func_9(vbytecount_711, vbytecountm_712, func, target_9)
and func_11(vbytecount_711, vbytecountm_712, target_17, target_11)
and func_12(vmodule_709, vtif_707, target_11, target_12)
and func_13(target_11, func, target_13)
and func_14(vmodule_709, vtif_707, target_14)
and func_15(vstrip_707, vbytecount_711, vtif_707, target_15)
and func_17(target_17)
and func_18(vbytecountm_712, target_18)
and func_19(target_19)
and vstrip_707.getType().hasName("uint32")
and vmodule_709.getType().hasName("const char[]")
and vbytecount_711.getType().hasName("uint64")
and vbytecountm_712.getType().hasName("tmsize_t")
and vtif_707.getType().hasName("TIFF *")
and vstrip_707.getFunction() = func
and vmodule_709.(LocalVariable).getFunction() = func
and vbytecount_711.(LocalVariable).getFunction() = func
and vbytecountm_712.(LocalVariable).getFunction() = func
and vtif_707.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
