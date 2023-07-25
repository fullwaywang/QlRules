/**
 * @name ffmpeg-27a99e2c7d450fef15594671eef4465c8a166bd7-track_header
 * @id cpp/ffmpeg/27a99e2c7d450fef15594671eef4465c8a166bd7/track-header
 * @description ffmpeg-27a99e2c7d450fef15594671eef4465c8a166bd7-libavformat/vividas.c-track_header CVE-2020-35964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="64"
		and not target_1.getValue()="1"
		and target_1.getParent().(AddExpr).getParent().(AddExpr).getAnOperand() instanceof AddExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="73"
		and not target_2.getValue()="0"
		and target_2.getParent().(BitwiseOrExpr).getParent().(BitwiseOrExpr).getLeftOperand() instanceof BitwiseOrExpr
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="78"
		and not target_3.getValue()="0"
		and target_3.getParent().(LShiftExpr).getParent().(BitwiseOrExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="8"
		and not target_4.getValue()="0"
		and target_4.getParent().(LShiftExpr).getParent().(BitwiseOrExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, Literal target_5) {
		target_5.getValue()="68"
		and not target_5.getValue()="409"
		and target_5.getParent().(LShiftExpr).getParent().(BitwiseOrExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Function func, Literal target_6) {
		target_6.getValue()="16"
		and not target_6.getValue()="0"
		and target_6.getParent().(LShiftExpr).getParent().(BitwiseOrExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Function func, Literal target_7) {
		target_7.getValue()="65"
		and not target_7.getValue()="0"
		and target_7.getParent().(LShiftExpr).getParent().(BitwiseOrExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Function func, Literal target_8) {
		target_8.getValue()="24"
		and not target_8.getValue()="0"
		and target_8.getParent().(LShiftExpr).getParent().(BitwiseOrExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vxd_size_382, Variable vlen_391, ExprStmt target_27) {
	exists(AddExpr target_9 |
		target_9.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_391
		and target_9.getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_391
		and target_9.getAnOperand().(DivExpr).getRightOperand() instanceof Literal
		and target_9.getParent().(AssignAddExpr).getRValue() = target_9
		and target_9.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vxd_size_382
		and target_9.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_10(Variable vxd_size_382, Variable voffset_384, Variable vdelta_407, AddExpr target_24, AddressOfExpr target_28, ExprStmt target_29) {
	exists(DoStmt target_10 |
		target_10.getCondition() instanceof Literal
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdelta_407
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vxd_size_382
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voffset_384
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="delta <= xd_size - offset"
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_24.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_28.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_10.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation()))
}

/*predicate func_11(Variable vxd_size_382, Variable voffset_384, Variable vdelta_407, BlockStmt target_30, AddExpr target_24, AddressOfExpr target_28, ExprStmt target_29) {
	exists(NotExpr target_11 |
		target_11.getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdelta_407
		and target_11.getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vxd_size_382
		and target_11.getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voffset_384
		and target_11.getParent().(IfStmt).getThen()=target_30
		and target_24.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_28.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_11.getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_11.getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation()))
}

*/
/*predicate func_12(RelationalOperation target_25, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_12.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_12.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_12.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_12.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="delta <= xd_size - offset"
		and target_12.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_12.getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
		and target_12.getEnclosingFunction() = func)
}

*/
/*predicate func_13(RelationalOperation target_25, Function func) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_13
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
		and target_13.getEnclosingFunction() = func)
}

*/
predicate func_14(Variable vxd_size_382, Variable voffset_384, AddExpr target_24, ExprStmt target_29, AddressOfExpr target_31) {
	exists(DoStmt target_14 |
		target_14.getCondition() instanceof Literal
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand() instanceof ArrayExpr
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vxd_size_382
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voffset_384
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="data_len[j] <= xd_size - offset"
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_24.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_29.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_14.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_31.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_16(Variable vj_281, Variable vst_359, Variable vdata_len_383, Variable vret_415, IfStmt target_16) {
		target_16.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_415
		and target_16.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_len_383
		and target_16.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_281
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extradata_size"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codecpar"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vst_359
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_freep")
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codecpar"
		and target_16.getThen().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
}

predicate func_17(Variable vj_281, Variable vdata_len_383, Variable voffset_384, ExprStmt target_17) {
		target_17.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_384
		and target_17.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_len_383
		and target_17.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_281
}

/*predicate func_18(Variable vj_281, Variable vdata_len_383, Variable vdelta_407, BlockStmt target_30, ArrayExpr target_18) {
		target_18.getArrayBase().(VariableAccess).getTarget()=vdata_len_383
		and target_18.getArrayOffset().(VariableAccess).getTarget()=vj_281
		and target_18.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vdelta_407
		and target_18.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_30
}

*/
predicate func_19(Variable vxd_size_382, VariableAccess target_19) {
		target_19.getTarget()=vxd_size_382
}

predicate func_21(Variable vxd_size_382, Variable vlen_391, VariableAccess target_21) {
		target_21.getTarget()=vlen_391
		and target_21.getParent().(AssignAddExpr).getRValue() = target_21
		and target_21.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vxd_size_382
}

predicate func_22(Variable vxd_size_382, VariableAccess target_22) {
		target_22.getTarget()=vxd_size_382
}

/*predicate func_23(Variable vj_281, Variable vdata_len_383, Variable vdelta_407, BlockStmt target_30, VariableAccess target_23) {
		target_23.getTarget()=vdelta_407
		and target_23.getParent().(GTExpr).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_len_383
		and target_23.getParent().(GTExpr).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_281
		and target_23.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_30
}

*/
predicate func_24(Variable vst_359, Variable vxd_size_382, AddExpr target_24) {
		target_24.getAnOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_24.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vxd_size_382
		and target_24.getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vxd_size_382
		and target_24.getAnOperand().(DivExpr).getRightOperand() instanceof Literal
		and target_24.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ff_alloc_extradata")
		and target_24.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="codecpar"
		and target_24.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vst_359
}

predicate func_25(Variable vdelta_407, BlockStmt target_30, RelationalOperation target_25) {
		 (target_25 instanceof GTExpr or target_25 instanceof LTExpr)
		and target_25.getGreaterOperand().(VariableAccess).getTarget()=vdelta_407
		and target_25.getLesserOperand() instanceof ArrayExpr
		and target_25.getParent().(IfStmt).getThen()=target_30
}

predicate func_26(RelationalOperation target_25, Function func, ReturnStmt target_26) {
		target_26.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
		and target_26.getEnclosingFunction() = func
}

predicate func_27(Variable vxd_size_382, Variable vlen_391, ExprStmt target_27) {
		target_27.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vxd_size_382
		and target_27.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vlen_391
}

predicate func_28(Variable voffset_384, AddressOfExpr target_28) {
		target_28.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=voffset_384
}

predicate func_29(Variable voffset_384, Variable vdelta_407, ExprStmt target_29) {
		target_29.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_384
		and target_29.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vdelta_407
}

predicate func_30(BlockStmt target_30) {
		target_30.getStmt(0) instanceof ReturnStmt
}

predicate func_31(Variable voffset_384, AddressOfExpr target_31) {
		target_31.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=voffset_384
}

from Function func, Variable vj_281, Variable vst_359, Variable vxd_size_382, Variable vdata_len_383, Variable voffset_384, Variable vlen_391, Variable vdelta_407, Variable vret_415, Literal target_0, Literal target_1, Literal target_2, Literal target_3, Literal target_4, Literal target_5, Literal target_6, Literal target_7, Literal target_8, IfStmt target_16, ExprStmt target_17, VariableAccess target_19, VariableAccess target_21, VariableAccess target_22, AddExpr target_24, RelationalOperation target_25, ReturnStmt target_26, ExprStmt target_27, AddressOfExpr target_28, ExprStmt target_29, BlockStmt target_30, AddressOfExpr target_31
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and func_7(func, target_7)
and func_8(func, target_8)
and not func_9(vxd_size_382, vlen_391, target_27)
and not func_10(vxd_size_382, voffset_384, vdelta_407, target_24, target_28, target_29)
and not func_14(vxd_size_382, voffset_384, target_24, target_29, target_31)
and func_16(vj_281, vst_359, vdata_len_383, vret_415, target_16)
and func_17(vj_281, vdata_len_383, voffset_384, target_17)
and func_19(vxd_size_382, target_19)
and func_21(vxd_size_382, vlen_391, target_21)
and func_22(vxd_size_382, target_22)
and func_24(vst_359, vxd_size_382, target_24)
and func_25(vdelta_407, target_30, target_25)
and func_26(target_25, func, target_26)
and func_27(vxd_size_382, vlen_391, target_27)
and func_28(voffset_384, target_28)
and func_29(voffset_384, vdelta_407, target_29)
and func_30(target_30)
and func_31(voffset_384, target_31)
and vj_281.getType().hasName("int")
and vst_359.getType().hasName("AVStream *")
and vxd_size_382.getType().hasName("int")
and vdata_len_383.getType().hasName("int[256]")
and voffset_384.getType().hasName("int")
and vlen_391.getType().hasName("uint64_t")
and vdelta_407.getType().hasName("unsigned int")
and vret_415.getType().hasName("int")
and vj_281.getParentScope+() = func
and vst_359.getParentScope+() = func
and vxd_size_382.getParentScope+() = func
and vdata_len_383.getParentScope+() = func
and voffset_384.getParentScope+() = func
and vlen_391.getParentScope+() = func
and vdelta_407.getParentScope+() = func
and vret_415.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
