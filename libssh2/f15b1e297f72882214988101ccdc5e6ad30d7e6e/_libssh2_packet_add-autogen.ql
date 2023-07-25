/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-_libssh2_packet_add
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/-libssh2-packet-add
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/packet.c-_libssh2_packet_add CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="exit_signal"
		and not target_0.getValue()="exit-signal"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="10"
		and not target_1.getValue()="9"
		and target_1.getParent().(SubExpr).getParent().(LTExpr).getGreaterOperand() instanceof SubExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vlen_775, ExprStmt target_16) {
	exists(AddExpr target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vlen_775
		and target_2.getAnOperand().(Literal).getValue()="9"
		and target_2.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vlen_775
		and target_2.getParent().(LTExpr).getGreaterOperand() instanceof SubExpr
		and target_2.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_16)
}

predicate func_3(Parameter vdata_415, Parameter vdatalen_416, BlockStmt target_17, RelationalOperation target_19) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="20"
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_3.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="exit-status"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_415
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="9"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="11"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_17
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_19.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vdatalen_416, BlockStmt target_20, RelationalOperation target_21) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getLesserOperand().(AddExpr).getValue()="25"
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_4.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_4.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_20
		and target_4.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_21.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vdatalen_416, BlockStmt target_20, RelationalOperation target_19) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="20"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_5.getAnOperand() instanceof NotExpr
		and target_5.getParent().(IfStmt).getThen()=target_20
		and target_19.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vdatalen_416, Variable vchannelp_423, BlockStmt target_22, RelationalOperation target_21, ExprStmt target_23, ExprStmt target_24) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=vchannelp_423
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="25"
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_6.getParent().(IfStmt).getThen()=target_22
		and target_21.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vdata_415, Parameter vdatalen_416, Variable vchannelp_423, Variable vnamelen_816, NotExpr target_25, PointerArithmeticOperation target_26, PointerArithmeticOperation target_27, RelationalOperation target_28, AddExpr target_29) {
	exists(IfStmt target_7 |
		target_7.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getValue()="25"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnamelen_816
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_423
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_415
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="13"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(SizeofExprOperator).getValue()="12"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnamelen_816
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_423
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vnamelen_816
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(2).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_7.getParent().(IfStmt).getCondition()=target_25
		and target_26.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_27.getAnOperand().(VariableAccess).getLocation())
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_28.getGreaterOperand().(VariableAccess).getLocation())
		and target_29.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_8(Parameter vdata_415, Variable vlen_775, BlockStmt target_20, NotExpr target_8) {
		target_8.getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_8.getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="exit-signal"
		and target_8.getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_415
		and target_8.getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="9"
		and target_8.getOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="11"
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_775
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getValue()="11"
		and target_8.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_20
}

*/
predicate func_9(Parameter vdata_415, Variable vlen_775, BlockStmt target_17, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vlen_775
		and target_9.getAnOperand().(SubExpr).getValue()="11"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="exit-status"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_415
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="9"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="11"
		and target_9.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_17
}

/*predicate func_10(Parameter vdata_415, Variable vlen_775, BlockStmt target_20, EqualityOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vlen_775
		and target_10.getAnOperand().(SubExpr).getValue()="11"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="exit-signal"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_415
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="9"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="11"
		and target_10.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_20
}

*/
predicate func_11(Variable vlen_775, ExprStmt target_16, VariableAccess target_11) {
		target_11.getTarget()=vlen_775
		and target_11.getParent().(LTExpr).getGreaterOperand() instanceof SubExpr
		and target_11.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_16
}

predicate func_12(Parameter vdatalen_416, VariableAccess target_12) {
		target_12.getTarget()=vdatalen_416
}

predicate func_13(Variable vchannelp_423, BlockStmt target_30, VariableAccess target_13) {
		target_13.getTarget()=vchannelp_423
		and target_13.getParent().(IfStmt).getThen()=target_30
}

predicate func_14(Variable vchannelp_423, BlockStmt target_22, VariableAccess target_14) {
		target_14.getTarget()=vchannelp_423
		and target_14.getParent().(IfStmt).getThen()=target_22
}

predicate func_15(Parameter vdatalen_416, ExprStmt target_16, RelationalOperation target_31, SubExpr target_15) {
		target_15.getLeftOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_15.getRightOperand() instanceof Literal
		and target_15.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_16
		and target_31.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_15.getLeftOperand().(VariableAccess).getLocation())
}

predicate func_16(Parameter vdata_415, Variable vlen_775, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_415
		and target_16.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="9"
		and target_16.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_775
}

predicate func_17(Parameter vdatalen_416, Variable vchannelp_423, BlockStmt target_17) {
		target_17.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_17.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="20"
		and target_17.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchannelp_423
		and target_17.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_channel_locate")
		and target_17.getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vchannelp_423
		and target_17.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="exit_status"
		and target_17.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_423
		and target_17.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_17.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_17.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
}

predicate func_19(Parameter vdatalen_416, RelationalOperation target_19) {
		 (target_19 instanceof GEExpr or target_19 instanceof LEExpr)
		and target_19.getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_19.getLesserOperand().(Literal).getValue()="20"
}

predicate func_20(Parameter vdatalen_416, Variable vchannelp_423, Variable vnamelen_816, BlockStmt target_20) {
		target_20.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_20.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="20"
		and target_20.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchannelp_423
		and target_20.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_channel_locate")
		and target_20.getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vchannelp_423
		and target_20.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnamelen_816
		and target_20.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="4294967294"
		and target_20.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_20.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_423
		and target_20.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_20.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_20.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_20.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
}

predicate func_21(Parameter vdatalen_416, RelationalOperation target_21) {
		 (target_21 instanceof GEExpr or target_21 instanceof LEExpr)
		and target_21.getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_21.getLesserOperand().(Literal).getValue()="20"
}

predicate func_22(Variable vchannelp_423, Variable vnamelen_816, BlockStmt target_22) {
		target_22.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnamelen_816
		and target_22.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="4294967294"
		and target_22.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_22.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_423
		and target_22.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_22.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_22.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_423
		and target_22.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_23(Variable vchannelp_423, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchannelp_423
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_channel_locate")
}

predicate func_24(Variable vchannelp_423, Variable vnamelen_816, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_423
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnamelen_816
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
}

predicate func_25(Variable vchannelp_423, NotExpr target_25) {
		target_25.getOperand().(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_25.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_423
}

predicate func_26(Parameter vdata_415, PointerArithmeticOperation target_26) {
		target_26.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_415
		and target_26.getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="9"
		and target_26.getAnOperand().(SizeofExprOperator).getValue()="12"
}

predicate func_27(Parameter vdata_415, PointerArithmeticOperation target_27) {
		target_27.getAnOperand().(VariableAccess).getTarget()=vdata_415
		and target_27.getAnOperand().(Literal).getValue()="1"
}

predicate func_28(Parameter vdatalen_416, RelationalOperation target_28) {
		 (target_28 instanceof GEExpr or target_28 instanceof LEExpr)
		and target_28.getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_28.getLesserOperand().(Literal).getValue()="5"
}

predicate func_29(Variable vnamelen_816, AddExpr target_29) {
		target_29.getAnOperand().(VariableAccess).getTarget()=vnamelen_816
		and target_29.getAnOperand().(Literal).getValue()="1"
}

predicate func_30(Parameter vdata_415, Variable vchannelp_423, BlockStmt target_30) {
		target_30.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="exit_status"
		and target_30.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_423
		and target_30.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_30.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_415
		and target_30.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="9"
		and target_30.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofExprOperator).getValue()="12"
}

predicate func_31(Parameter vdatalen_416, RelationalOperation target_31) {
		 (target_31 instanceof GEExpr or target_31 instanceof LEExpr)
		and target_31.getGreaterOperand().(VariableAccess).getTarget()=vdatalen_416
		and target_31.getLesserOperand().(Literal).getValue()="9"
}

from Function func, Parameter vdata_415, Parameter vdatalen_416, Variable vchannelp_423, Variable vlen_775, Variable vnamelen_816, StringLiteral target_0, Literal target_1, EqualityOperation target_9, VariableAccess target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, SubExpr target_15, ExprStmt target_16, BlockStmt target_17, RelationalOperation target_19, BlockStmt target_20, RelationalOperation target_21, BlockStmt target_22, ExprStmt target_23, ExprStmt target_24, NotExpr target_25, PointerArithmeticOperation target_26, PointerArithmeticOperation target_27, RelationalOperation target_28, AddExpr target_29, BlockStmt target_30, RelationalOperation target_31
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vlen_775, target_16)
and not func_3(vdata_415, vdatalen_416, target_17, target_19)
and not func_4(vdatalen_416, target_20, target_21)
and not func_5(vdatalen_416, target_20, target_19)
and not func_6(vdatalen_416, vchannelp_423, target_22, target_21, target_23, target_24)
and not func_7(vdata_415, vdatalen_416, vchannelp_423, vnamelen_816, target_25, target_26, target_27, target_28, target_29)
and func_9(vdata_415, vlen_775, target_17, target_9)
and func_11(vlen_775, target_16, target_11)
and func_12(vdatalen_416, target_12)
and func_13(vchannelp_423, target_30, target_13)
and func_14(vchannelp_423, target_22, target_14)
and func_15(vdatalen_416, target_16, target_31, target_15)
and func_16(vdata_415, vlen_775, target_16)
and func_17(vdatalen_416, vchannelp_423, target_17)
and func_19(vdatalen_416, target_19)
and func_20(vdatalen_416, vchannelp_423, vnamelen_816, target_20)
and func_21(vdatalen_416, target_21)
and func_22(vchannelp_423, vnamelen_816, target_22)
and func_23(vchannelp_423, target_23)
and func_24(vchannelp_423, vnamelen_816, target_24)
and func_25(vchannelp_423, target_25)
and func_26(vdata_415, target_26)
and func_27(vdata_415, target_27)
and func_28(vdatalen_416, target_28)
and func_29(vnamelen_816, target_29)
and func_30(vdata_415, vchannelp_423, target_30)
and func_31(vdatalen_416, target_31)
and vdata_415.getType().hasName("unsigned char *")
and vdatalen_416.getType().hasName("size_t")
and vchannelp_423.getType().hasName("LIBSSH2_CHANNEL *")
and vlen_775.getType().hasName("uint32_t")
and vnamelen_816.getType().hasName("uint32_t")
and vdata_415.getParentScope+() = func
and vdatalen_416.getParentScope+() = func
and vchannelp_423.getParentScope+() = func
and vlen_775.getParentScope+() = func
and vnamelen_816.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
