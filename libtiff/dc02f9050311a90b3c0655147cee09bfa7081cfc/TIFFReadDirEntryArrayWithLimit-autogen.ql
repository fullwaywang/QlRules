/**
 * @name libtiff-dc02f9050311a90b3c0655147cee09bfa7081cfc-TIFFReadDirEntryArrayWithLimit
 * @id cpp/libtiff/dc02f9050311a90b3c0655147cee09bfa7081cfc/TIFFReadDirEntryArrayWithLimit
 * @description libtiff-dc02f9050311a90b3c0655147cee09bfa7081cfc-libtiff/tif_dirread.c-TIFFReadDirEntryArrayWithLimit CVE-2017-12944
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtif_772, Variable vdatasize_776, RelationalOperation target_9, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_772
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2048"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatasize_776
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="tif_size"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_772
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_9.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtif_772, Variable vdatasize_776, Variable vdata_777, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_772
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2048"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_772
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="524288"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatasize_776
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="524288"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatasize_776
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdata_777
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getElse().(BlockStmt).getStmt(1) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_1)
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_10.getLesserOperand().(VariableAccess).getLocation())
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vdata_777, NotExpr target_13, ExprStmt target_11, ExprStmt target_12) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdata_777
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_3(Parameter vtif_772, Variable vdatasize_776, Variable vdata_777, Variable verr_813, Variable voffset_814, RelationalOperation target_10, BitwiseAndExpr target_14, ExprStmt target_7, ExprStmt target_15, AddressOfExpr target_16) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_772
		and target_3.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2048"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen() instanceof ExprStmt
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_813
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFReadDirEntryDataAndRealloc")
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_772
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_814
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdatasize_776
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdata_777
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_14.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_15.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_16.getOperand().(VariableAccess).getLocation().isBefore(target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vtif_772, Variable vdatasize_776, Variable vdata_777, Variable verr_831, Variable voffset_832, RelationalOperation target_17, BitwiseAndExpr target_18, ExprStmt target_8, ExprStmt target_12, AddressOfExpr target_19) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_772
		and target_4.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2048"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen() instanceof ExprStmt
		and target_4.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_831
		and target_4.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFReadDirEntryDataAndRealloc")
		and target_4.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_772
		and target_4.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_832
		and target_4.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdatasize_776
		and target_4.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdata_777
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_18.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_4.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_19.getOperand().(VariableAccess).getLocation().isBefore(target_4.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_5(Parameter vtif_772, Parameter vcount_772, Variable vtypesize_775, Variable vdata_777, Function func, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdata_777
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFCheckMalloc")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_772
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcount_772
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtypesize_775
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ReadDirEntryArray"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vdata_777, Function func, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_777
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vtif_772, Variable vdatasize_776, Variable vdata_777, Variable verr_813, Variable voffset_814, RelationalOperation target_10, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_813
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFReadDirEntryData")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_772
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_814
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdatasize_776
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_777
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_8(Parameter vtif_772, Variable vdatasize_776, Variable vdata_777, Variable verr_831, Variable voffset_832, RelationalOperation target_17, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_831
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFReadDirEntryData")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_772
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_832
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdatasize_776
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_777
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

predicate func_9(Variable vdatasize_776, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vdatasize_776
		and target_9.getLesserOperand() instanceof Literal
}

predicate func_10(Variable vdatasize_776, RelationalOperation target_10) {
		 (target_10 instanceof GEExpr or target_10 instanceof LEExpr)
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vdatasize_776
		and target_10.getGreaterOperand().(Literal).getValue()="4"
}

predicate func_11(Variable vdata_777, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_777
}

predicate func_12(Variable vdatasize_776, Variable vdata_777, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_777
		and target_12.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tdir_offset"
		and target_12.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFFDirEntry *")
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdatasize_776
}

predicate func_13(Parameter vtif_772, NotExpr target_13) {
		target_13.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_13.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_772
		and target_13.getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="524288"
}

predicate func_14(Parameter vtif_772, BitwiseAndExpr target_14) {
		target_14.getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_14.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_772
		and target_14.getRightOperand().(Literal).getValue()="128"
}

predicate func_15(Variable vdatasize_776, Variable vdata_777, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_777
		and target_15.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tdir_offset"
		and target_15.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFFDirEntry *")
		and target_15.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdatasize_776
}

predicate func_16(Variable voffset_814, AddressOfExpr target_16) {
		target_16.getOperand().(VariableAccess).getTarget()=voffset_814
}

predicate func_17(Variable vdatasize_776, RelationalOperation target_17) {
		 (target_17 instanceof GEExpr or target_17 instanceof LEExpr)
		and target_17.getLesserOperand().(VariableAccess).getTarget()=vdatasize_776
		and target_17.getGreaterOperand().(Literal).getValue()="8"
}

predicate func_18(Parameter vtif_772, BitwiseAndExpr target_18) {
		target_18.getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_18.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_772
		and target_18.getRightOperand().(Literal).getValue()="128"
}

predicate func_19(Variable voffset_832, AddressOfExpr target_19) {
		target_19.getOperand().(VariableAccess).getTarget()=voffset_832
}

from Function func, Parameter vtif_772, Parameter vcount_772, Variable vtypesize_775, Variable vdatasize_776, Variable vdata_777, Variable verr_813, Variable voffset_814, Variable verr_831, Variable voffset_832, ExprStmt target_5, IfStmt target_6, ExprStmt target_7, ExprStmt target_8, RelationalOperation target_9, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12, NotExpr target_13, BitwiseAndExpr target_14, ExprStmt target_15, AddressOfExpr target_16, RelationalOperation target_17, BitwiseAndExpr target_18, AddressOfExpr target_19
where
not func_0(vtif_772, vdatasize_776, target_9, func)
and not func_1(vtif_772, vdatasize_776, vdata_777, target_10, target_11, target_12, func)
and not func_3(vtif_772, vdatasize_776, vdata_777, verr_813, voffset_814, target_10, target_14, target_7, target_15, target_16)
and not func_4(vtif_772, vdatasize_776, vdata_777, verr_831, voffset_832, target_17, target_18, target_8, target_12, target_19)
and func_5(vtif_772, vcount_772, vtypesize_775, vdata_777, func, target_5)
and func_6(vdata_777, func, target_6)
and func_7(vtif_772, vdatasize_776, vdata_777, verr_813, voffset_814, target_10, target_7)
and func_8(vtif_772, vdatasize_776, vdata_777, verr_831, voffset_832, target_17, target_8)
and func_9(vdatasize_776, target_9)
and func_10(vdatasize_776, target_10)
and func_11(vdata_777, target_11)
and func_12(vdatasize_776, vdata_777, target_12)
and func_13(vtif_772, target_13)
and func_14(vtif_772, target_14)
and func_15(vdatasize_776, vdata_777, target_15)
and func_16(voffset_814, target_16)
and func_17(vdatasize_776, target_17)
and func_18(vtif_772, target_18)
and func_19(voffset_832, target_19)
and vtif_772.getType().hasName("TIFF *")
and vcount_772.getType().hasName("uint32 *")
and vtypesize_775.getType().hasName("int")
and vdatasize_776.getType().hasName("uint32")
and vdata_777.getType().hasName("void *")
and verr_813.getType().hasName("TIFFReadDirEntryErr")
and voffset_814.getType().hasName("uint32")
and verr_831.getType().hasName("TIFFReadDirEntryErr")
and voffset_832.getType().hasName("uint64")
and vtif_772.getFunction() = func
and vcount_772.getFunction() = func
and vtypesize_775.(LocalVariable).getFunction() = func
and vdatasize_776.(LocalVariable).getFunction() = func
and vdata_777.(LocalVariable).getFunction() = func
and verr_813.(LocalVariable).getFunction() = func
and voffset_814.(LocalVariable).getFunction() = func
and verr_831.(LocalVariable).getFunction() = func
and voffset_832.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
