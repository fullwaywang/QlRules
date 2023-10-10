/**
 * @name libtiff-25f9ffa56548c1846c4a1f19308b7f561f7b1ab0-main
 * @id cpp/libtiff/25f9ffa56548c1846c4a1f19308b7f561f7b1ab0/main
 * @description libtiff-25f9ffa56548c1846c4a1f19308b7f561f7b1ab0-tools/tiff2bw.c-main CVE-2017-16232
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vin_115, ExprStmt target_28, ExprStmt target_35, VariableAccess target_0) {
		target_0.getTarget()=vin_115
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFClose")
		and target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_35.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="0"
		and target_1.getParent().(UnaryMinusExpr).getParent().(ReturnStmt).getExpr() instanceof UnaryMinusExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="1"
		and not target_2.getValue()="0"
		and target_2.getParent().(UnaryMinusExpr).getParent().(ReturnStmt).getExpr() instanceof UnaryMinusExpr
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vin_115, FunctionCall target_3) {
		target_3.getTarget().hasName("TIFFClose")
		and not target_3.getTarget().hasName("_TIFFfree")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vin_115
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="1"
		and not target_4.getValue()="0"
		and target_4.getParent().(UnaryMinusExpr).getParent().(ReturnStmt).getExpr() instanceof UnaryMinusExpr
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Variable vin_115, FunctionCall target_5) {
		target_5.getTarget().hasName("TIFFClose")
		and not target_5.getTarget().hasName("_TIFFfree")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vin_115
}

predicate func_6(Function func, Literal target_6) {
		target_6.getValue()="1"
		and not target_6.getValue()="0"
		and target_6.getParent().(UnaryMinusExpr).getParent().(ReturnStmt).getExpr() instanceof UnaryMinusExpr
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vin_115, ExprStmt target_35) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vin_115
		and target_7.getRValue().(Literal).getValue()="0"
		and target_35.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getLValue().(VariableAccess).getLocation()))
}

predicate func_8(Variable vout_115, EqualityOperation target_37, ExprStmt target_38) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(VariableAccess).getTarget()=vout_115
		and target_8.getRValue().(Literal).getValue()="0"
		and target_37.getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getLValue().(VariableAccess).getLocation())
		and target_8.getLValue().(VariableAccess).getLocation().isBefore(target_38.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_9(Variable vinbuf_127, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vinbuf_127
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_9))
}

predicate func_10(Variable voutbuf_127, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voutbuf_127
		and target_10.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_10))
}

predicate func_11(LogicalAndExpr target_39, Function func) {
	exists(GotoStmt target_11 |
		target_11.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_11
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(LogicalAndExpr target_40, Function func) {
	exists(GotoStmt target_12 |
		target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_40
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(LogicalAndExpr target_41, Function func) {
	exists(GotoStmt target_13 |
		target_13.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_13
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(EqualityOperation target_42, Function func) {
	exists(GotoStmt target_14 |
		target_14.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_14
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(EqualityOperation target_37, Function func) {
	exists(GotoStmt target_15 |
		target_15.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_15
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(RelationalOperation target_43, Function func) {
	exists(GotoStmt target_16 |
		target_16.getParent().(IfStmt).getCondition()=target_43
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(Variable vinbuf_127, PointerArithmeticOperation target_44, Function func) {
	exists(IfStmt target_17 |
		target_17.getCondition().(VariableAccess).getTarget()=vinbuf_127
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinbuf_127
		and (func.getEntryPoint().(BlockStmt).getStmt(51)=target_17 or func.getEntryPoint().(BlockStmt).getStmt(51).getFollowingStmt()=target_17)
		and target_44.getAnOperand().(VariableAccess).getLocation().isBefore(target_17.getCondition().(VariableAccess).getLocation()))
}

predicate func_19(Variable voutbuf_127, RelationalOperation target_45, Function func) {
	exists(IfStmt target_19 |
		target_19.getCondition().(VariableAccess).getTarget()=voutbuf_127
		and target_19.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_19.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutbuf_127
		and (func.getEntryPoint().(BlockStmt).getStmt(52)=target_19 or func.getEntryPoint().(BlockStmt).getStmt(52).getFollowingStmt()=target_19)
		and target_45.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_19.getCondition().(VariableAccess).getLocation()))
}

predicate func_22(Variable vinbuf_127, Function func) {
	exists(IfStmt target_22 |
		target_22.getCondition().(VariableAccess).getTarget()=vinbuf_127
		and target_22.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_22.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinbuf_127
		and (func.getEntryPoint().(BlockStmt).getStmt(57)=target_22 or func.getEntryPoint().(BlockStmt).getStmt(57).getFollowingStmt()=target_22))
}

predicate func_23(Variable voutbuf_127, Function func) {
	exists(IfStmt target_23 |
		target_23.getCondition().(VariableAccess).getTarget()=voutbuf_127
		and target_23.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_23.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutbuf_127
		and (func.getEntryPoint().(BlockStmt).getStmt(58)=target_23 or func.getEntryPoint().(BlockStmt).getStmt(58).getFollowingStmt()=target_23))
}

predicate func_24(Function func) {
	exists(IfStmt target_24 |
		target_24.getCondition().(VariableAccess).getType().hasName("TIFF *")
		and target_24.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFClose")
		and target_24.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("TIFF *")
		and (func.getEntryPoint().(BlockStmt).getStmt(59)=target_24 or func.getEntryPoint().(BlockStmt).getStmt(59).getFollowingStmt()=target_24))
}

predicate func_25(Variable vin_115, ExprStmt target_46, Function func) {
	exists(IfStmt target_25 |
		target_25.getCondition().(VariableAccess).getTarget()=vin_115
		and target_25.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(60)=target_25 or func.getEntryPoint().(BlockStmt).getStmt(60).getFollowingStmt()=target_25)
		and target_25.getCondition().(VariableAccess).getLocation().isBefore(target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_26(Variable vin_115, LogicalAndExpr target_39, ExprStmt target_26) {
		target_26.getExpr().(FunctionCall).getTarget().hasName("TIFFClose")
		and target_26.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_115
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
}

predicate func_27(LogicalAndExpr target_39, Function func, ReturnStmt target_27) {
		target_27.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
		and target_27.getEnclosingFunction() = func
}

predicate func_28(Variable vin_115, LogicalAndExpr target_40, ExprStmt target_28) {
		target_28.getExpr().(FunctionCall).getTarget().hasName("TIFFClose")
		and target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_115
		and target_28.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_40
}

predicate func_29(Variable vin_115, VariableAccess target_29) {
		target_29.getTarget()=vin_115
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_30(LogicalAndExpr target_40, Function func, ReturnStmt target_30) {
		target_30.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_40
		and target_30.getEnclosingFunction() = func
}

predicate func_31(LogicalAndExpr target_41, Function func, ReturnStmt target_31) {
		target_31.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_31.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
		and target_31.getEnclosingFunction() = func
}

predicate func_32(EqualityOperation target_42, Function func, ReturnStmt target_32) {
		target_32.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_32.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_32.getEnclosingFunction() = func
}

predicate func_33(EqualityOperation target_37, Function func, ReturnStmt target_33) {
		target_33.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37
		and target_33.getEnclosingFunction() = func
}

predicate func_34(RelationalOperation target_43, Function func, ReturnStmt target_34) {
		target_34.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_34.getParent().(IfStmt).getCondition()=target_43
		and target_34.getEnclosingFunction() = func
}

predicate func_35(Variable vin_115, ExprStmt target_35) {
		target_35.getExpr().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_35.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_115
		and target_35.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="258"
		and target_35.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint16")
}

predicate func_37(Variable vout_115, EqualityOperation target_37) {
		target_37.getAnOperand().(VariableAccess).getTarget()=vout_115
		and target_37.getAnOperand().(Literal).getValue()="0"
}

predicate func_38(Variable vout_115, ExprStmt target_38) {
		target_38.getExpr().(FunctionCall).getTarget().hasName("TIFFSetField")
		and target_38.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_115
		and target_38.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="256"
		and target_38.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_39(LogicalAndExpr target_39) {
		target_39.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
}

predicate func_40(LogicalAndExpr target_40) {
		target_40.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_40.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_40.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_40.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
}

predicate func_41(LogicalAndExpr target_41) {
		target_41.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_41.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_41.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_41.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
}

predicate func_42(EqualityOperation target_42) {
		target_42.getAnOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_42.getAnOperand().(Literal).getValue()="8"
}

predicate func_43(Variable vin_115, Variable vinbuf_127, RelationalOperation target_43) {
		 (target_43 instanceof GTExpr or target_43 instanceof LTExpr)
		and target_43.getLesserOperand().(FunctionCall).getTarget().hasName("TIFFReadScanline")
		and target_43.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_115
		and target_43.getLesserOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vinbuf_127
		and target_43.getLesserOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("tsample_t")
		and target_43.getLesserOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_43.getLesserOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_43.getLesserOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("tsample_t")
		and target_43.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_44(Variable vinbuf_127, PointerArithmeticOperation target_44) {
		target_44.getAnOperand().(VariableAccess).getTarget()=vinbuf_127
		and target_44.getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_44.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("tsize_t")
}

predicate func_45(Variable vout_115, Variable voutbuf_127, RelationalOperation target_45) {
		 (target_45 instanceof GTExpr or target_45 instanceof LTExpr)
		and target_45.getLesserOperand().(FunctionCall).getTarget().hasName("TIFFWriteScanline")
		and target_45.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_115
		and target_45.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voutbuf_127
		and target_45.getLesserOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_45.getLesserOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_45.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_46(Variable vin_115, ExprStmt target_46) {
		target_46.getExpr().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_115
		and target_46.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="256"
		and target_46.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint32")
}

from Function func, Variable vin_115, Variable vout_115, Variable vinbuf_127, Variable voutbuf_127, VariableAccess target_0, Literal target_1, Literal target_2, FunctionCall target_3, Literal target_4, FunctionCall target_5, Literal target_6, ExprStmt target_26, ReturnStmt target_27, ExprStmt target_28, VariableAccess target_29, ReturnStmt target_30, ReturnStmt target_31, ReturnStmt target_32, ReturnStmt target_33, ReturnStmt target_34, ExprStmt target_35, EqualityOperation target_37, ExprStmt target_38, LogicalAndExpr target_39, LogicalAndExpr target_40, LogicalAndExpr target_41, EqualityOperation target_42, RelationalOperation target_43, PointerArithmeticOperation target_44, RelationalOperation target_45, ExprStmt target_46
where
func_0(vin_115, target_28, target_35, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(vin_115, target_3)
and func_4(func, target_4)
and func_5(vin_115, target_5)
and func_6(func, target_6)
and not func_7(vin_115, target_35)
and not func_8(vout_115, target_37, target_38)
and not func_9(vinbuf_127, func)
and not func_10(voutbuf_127, func)
and not func_11(target_39, func)
and not func_12(target_40, func)
and not func_13(target_41, func)
and not func_14(target_42, func)
and not func_15(target_37, func)
and not func_16(target_43, func)
and not func_17(vinbuf_127, target_44, func)
and not func_19(voutbuf_127, target_45, func)
and not func_22(vinbuf_127, func)
and not func_23(voutbuf_127, func)
and not func_24(func)
and not func_25(vin_115, target_46, func)
and func_26(vin_115, target_39, target_26)
and func_27(target_39, func, target_27)
and func_28(vin_115, target_40, target_28)
and func_29(vin_115, target_29)
and func_30(target_40, func, target_30)
and func_31(target_41, func, target_31)
and func_32(target_42, func, target_32)
and func_33(target_37, func, target_33)
and func_34(target_43, func, target_34)
and func_35(vin_115, target_35)
and func_37(vout_115, target_37)
and func_38(vout_115, target_38)
and func_39(target_39)
and func_40(target_40)
and func_41(target_41)
and func_42(target_42)
and func_43(vin_115, vinbuf_127, target_43)
and func_44(vinbuf_127, target_44)
and func_45(vout_115, voutbuf_127, target_45)
and func_46(vin_115, target_46)
and vin_115.getType().hasName("TIFF *")
and vout_115.getType().hasName("TIFF *")
and vinbuf_127.getType().hasName("unsigned char *")
and voutbuf_127.getType().hasName("unsigned char *")
and vin_115.(LocalVariable).getFunction() = func
and vout_115.(LocalVariable).getFunction() = func
and vinbuf_127.(LocalVariable).getFunction() = func
and voutbuf_127.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
