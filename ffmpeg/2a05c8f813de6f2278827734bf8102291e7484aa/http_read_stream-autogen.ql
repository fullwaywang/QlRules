/**
 * @name ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-http_read_stream
 * @id cpp/ffmpeg/2a05c8f813de6f2278827734bf8102291e7484aa/http-read-stream
 * @description ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-libavformat/http.c-http_read_stream CVE-2016-10190
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="22"
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vs_1237, NotExpr target_35, Literal target_2) {
		target_2.getValue()="0"
		and not target_2.getValue()="16"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="56"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Chunked encoding data size: %ld'\n"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_35.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

/*predicate func_3(Function func, StringLiteral target_3) {
		target_3.getValue()="Chunked encoding data size: %ld'\n"
		and not target_3.getValue()="Chunked encoding data size: %lu'\n"
		and target_3.getEnclosingFunction() = func
}

*/
predicate func_4(Function func, StringLiteral target_4) {
		target_4.getValue()="Will reconnect at %ld error=%s.\n"
		and not target_4.getValue()="Invalid chunk size %lu\n"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, StringLiteral target_5) {
		target_5.getValue()="Failed to reconnect at %ld.\n"
		and not target_5.getValue()="Will reconnect at %lu error=%s.\n"
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Variable vs_1237, BlockStmt target_36, LogicalAndExpr target_37, NotExpr target_38) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_6.getAnOperand().(Literal).getValue()="18446744073709551615"
		and target_6.getParent().(IfStmt).getThen()=target_36
		and target_37.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_38.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Variable vs_1237, Variable vline_1252, RelationalOperation target_39, ExprStmt target_40) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_7.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_7.getRValue().(FunctionCall).getTarget().hasName("strtoull")
		and target_7.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_1252
		and target_7.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_7.getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_39.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_40.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Variable vs_1237, Parameter vh_1235, NotExpr target_35, ExprStmt target_42, ExprStmt target_18) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="18446744073709551615"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_1235
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid chunk size %lu\n"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_8.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_8.getParent().(IfStmt).getCondition()=target_35
		and target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_42.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_9(Variable vs_1237, RelationalOperation target_43, ExprStmt target_42) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="chunksize"
		and target_9.getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_43.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getQualifier().(VariableAccess).getLocation())
		and target_9.getQualifier().(VariableAccess).getLocation().isBefore(target_42.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_10(LogicalOrExpr target_44, Function func) {
	exists(ReturnStmt target_10 |
		target_10.getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
		and target_10.getEnclosingFunction() = func)
}

*/
predicate func_12(Parameter vh_1235, Variable vtarget_1276, EqualityOperation target_45, ExprStmt target_23, ExprStmt target_46) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_1235
		and target_12.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_12.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed to reconnect at %lu.\n"
		and target_12.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtarget_1276
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_46.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_13(Variable vs_1237, LogicalOrExpr target_44, IfStmt target_13) {
		target_13.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="reconnect_delay"
		and target_13.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_13.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="reconnect_delay_max"
		and target_13.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_13.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

/*predicate func_14(Variable vread_ret_1238, FunctionCall target_14) {
		target_14.getTarget().hasName("av_make_error_string")
		and target_14.getArgument(0).(ArrayAggregateLiteral).getValue()="{...}"
		and target_14.getArgument(0).(ArrayAggregateLiteral).getElementExpr(0).(Literal).getValue()="0"
		and target_14.getArgument(1).(Literal).getValue()="64"
		and target_14.getArgument(2).(VariableAccess).getTarget()=vread_ret_1238
}

*/
predicate func_15(Variable vs_1237, LogicalOrExpr target_44, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("av_usleep")
		and target_15.getExpr().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getValue()="1000000"
		and target_15.getExpr().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="reconnect_delay"
		and target_15.getExpr().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

predicate func_16(Variable vs_1237, LogicalOrExpr target_44, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="reconnect_delay"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="reconnect_delay"
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

predicate func_17(Variable vread_ret_1238, EqualityOperation target_45, ReturnStmt target_17) {
		target_17.getExpr().(VariableAccess).getTarget()=vread_ret_1238
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45
}

predicate func_18(Parameter vbuf_1235, Parameter vsize_1235, Parameter vh_1235, Variable vread_ret_1238, LogicalOrExpr target_44, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_ret_1238
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("http_buf_read")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_1235
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_1235
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_1235
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

predicate func_19(Variable vs_1237, BlockStmt target_36, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="chunksize"
		and target_19.getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_19.getParent().(GEExpr).getLesserOperand() instanceof Literal
		and target_19.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_36
}

predicate func_20(Variable vs_1237, PointerFieldAccess target_20) {
		target_20.getTarget().getName()="chunksize"
		and target_20.getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_20.getParent().(AssignExpr).getLValue() = target_20
		and target_20.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_21(LogicalOrExpr target_44, Function func, DeclStmt target_21) {
		target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
		and target_21.getEnclosingFunction() = func
}

/*predicate func_22(Variable vs_1237, Parameter vh_1235, Variable vread_ret_1238, PointerFieldAccess target_22) {
		target_22.getTarget().getName()="off"
		and target_22.getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_1235
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="32"
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("av_make_error_string")
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ArrayAggregateLiteral).getValue()="{...}"
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ArrayAggregateLiteral).getElementExpr(0).(Literal).getValue()="0"
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1).(Literal).getValue()="64"
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vread_ret_1238
}

*/
predicate func_23(Parameter vh_1235, Variable vseek_ret_1239, Variable vtarget_1276, LogicalOrExpr target_44, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vseek_ret_1239
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("http_seek_internal")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_1235
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtarget_1276
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

predicate func_24(Variable vline_1252, VariableAccess target_24) {
		target_24.getTarget()=vline_1252
		and target_24.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

/*predicate func_27(Variable vs_1237, Parameter vh_1235, Variable vread_ret_1238, VariableAccess target_27) {
		target_27.getTarget()=vh_1235
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="32"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="off"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("av_make_error_string")
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ArrayAggregateLiteral).getValue()="{...}"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ArrayAggregateLiteral).getElementExpr(0).(Literal).getValue()="0"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1).(Literal).getValue()="64"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vread_ret_1238
}

*/
predicate func_29(Parameter vh_1235, Variable vtarget_1276, VariableAccess target_29) {
		target_29.getTarget()=vh_1235
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtarget_1276
}

predicate func_31(Variable vs_1237, BlockStmt target_36, RelationalOperation target_31) {
		 (target_31 instanceof GEExpr or target_31 instanceof LEExpr)
		and target_31.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_31.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_31.getLesserOperand() instanceof Literal
		and target_31.getParent().(IfStmt).getThen()=target_36
}

predicate func_32(Variable vs_1237, Variable vline_1252, AssignExpr target_32) {
		target_32.getLValue().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_32.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_32.getRValue().(FunctionCall).getTarget().hasName("strtoll")
		and target_32.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_1252
		and target_32.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_32.getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_33(Parameter vh_1235, Variable vtarget_1276, ExprStmt target_18, VariableAccess target_33) {
		target_33.getTarget()=vtarget_1276
		and target_33.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_33.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_1235
		and target_33.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_33.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_33.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_35(Variable vs_1237, NotExpr target_35) {
		target_35.getOperand().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_35.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
}

predicate func_36(Variable vs_1237, Variable vline_1252, BlockStmt target_36) {
		target_36.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_36.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_36.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_1252
		and target_36.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr() instanceof AssignExpr
		and target_36.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_36.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_36.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="56"
		and target_36.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_36.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_36.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
}

predicate func_37(Variable vs_1237, LogicalAndExpr target_37) {
		target_37.getAnOperand().(PointerFieldAccess).getTarget().getName()="end_chunked_post"
		and target_37.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_37.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="end_header"
		and target_37.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
}

predicate func_38(Variable vs_1237, NotExpr target_38) {
		target_38.getOperand().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_38.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
}

predicate func_39(Variable vs_1237, Variable vline_1252, RelationalOperation target_39) {
		 (target_39 instanceof GTExpr or target_39 instanceof LTExpr)
		and target_39.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("http_get_line")
		and target_39.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1237
		and target_39.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vline_1252
		and target_39.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="32"
		and target_39.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_40(Variable vs_1237, ExprStmt target_40) {
		target_40.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_40.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_40.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="56"
		and target_40.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_40.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_40.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
}

predicate func_42(Variable vs_1237, Parameter vh_1235, ExprStmt target_42) {
		target_42.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_42.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_1235
		and target_42.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_42.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_42.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="off"
		and target_42.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_42.getExpr().(FunctionCall).getArgument(4) instanceof FunctionCall
}

predicate func_43(Variable vs_1237, RelationalOperation target_43) {
		 (target_43 instanceof GTExpr or target_43 instanceof LTExpr)
		and target_43.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="reconnect_delay"
		and target_43.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_43.getLesserOperand().(PointerFieldAccess).getTarget().getName()="reconnect_delay_max"
		and target_43.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
}

predicate func_44(Variable vs_1237, Parameter vh_1235, Variable vread_ret_1238, LogicalOrExpr target_44) {
		target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vread_ret_1238
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="reconnect"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="is_streamed"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="reconnect_streamed"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="off"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vread_ret_1238
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="reconnect_at_eof"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="is_streamed"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_1235
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="reconnect_streamed"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1237
}

predicate func_45(Variable vseek_ret_1239, Variable vtarget_1276, EqualityOperation target_45) {
		target_45.getAnOperand().(VariableAccess).getTarget()=vseek_ret_1239
		and target_45.getAnOperand().(VariableAccess).getTarget()=vtarget_1276
}

predicate func_46(Parameter vh_1235, Variable vtarget_1276, ExprStmt target_46) {
		target_46.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_1235
		and target_46.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_46.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_46.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtarget_1276
}

from Function func, Parameter vbuf_1235, Parameter vsize_1235, Variable vs_1237, Parameter vh_1235, Variable vread_ret_1238, Variable vseek_ret_1239, Variable vline_1252, Variable vtarget_1276, Literal target_1, Literal target_2, StringLiteral target_4, StringLiteral target_5, IfStmt target_13, ExprStmt target_15, ExprStmt target_16, ReturnStmt target_17, ExprStmt target_18, PointerFieldAccess target_19, PointerFieldAccess target_20, DeclStmt target_21, ExprStmt target_23, VariableAccess target_24, VariableAccess target_29, RelationalOperation target_31, AssignExpr target_32, VariableAccess target_33, NotExpr target_35, BlockStmt target_36, LogicalAndExpr target_37, NotExpr target_38, RelationalOperation target_39, ExprStmt target_40, ExprStmt target_42, RelationalOperation target_43, LogicalOrExpr target_44, EqualityOperation target_45, ExprStmt target_46
where
func_1(func, target_1)
and func_2(vs_1237, target_35, target_2)
and func_4(func, target_4)
and func_5(func, target_5)
and not func_6(vs_1237, target_36, target_37, target_38)
and not func_7(vs_1237, vline_1252, target_39, target_40)
and not func_8(vs_1237, vh_1235, target_35, target_42, target_18)
and not func_12(vh_1235, vtarget_1276, target_45, target_23, target_46)
and func_13(vs_1237, target_44, target_13)
and func_15(vs_1237, target_44, target_15)
and func_16(vs_1237, target_44, target_16)
and func_17(vread_ret_1238, target_45, target_17)
and func_18(vbuf_1235, vsize_1235, vh_1235, vread_ret_1238, target_44, target_18)
and func_19(vs_1237, target_36, target_19)
and func_20(vs_1237, target_20)
and func_21(target_44, func, target_21)
and func_23(vh_1235, vseek_ret_1239, vtarget_1276, target_44, target_23)
and func_24(vline_1252, target_24)
and func_29(vh_1235, vtarget_1276, target_29)
and func_31(vs_1237, target_36, target_31)
and func_32(vs_1237, vline_1252, target_32)
and func_33(vh_1235, vtarget_1276, target_18, target_33)
and func_35(vs_1237, target_35)
and func_36(vs_1237, vline_1252, target_36)
and func_37(vs_1237, target_37)
and func_38(vs_1237, target_38)
and func_39(vs_1237, vline_1252, target_39)
and func_40(vs_1237, target_40)
and func_42(vs_1237, vh_1235, target_42)
and func_43(vs_1237, target_43)
and func_44(vs_1237, vh_1235, vread_ret_1238, target_44)
and func_45(vseek_ret_1239, vtarget_1276, target_45)
and func_46(vh_1235, vtarget_1276, target_46)
and vbuf_1235.getType().hasName("uint8_t *")
and vsize_1235.getType().hasName("int")
and vs_1237.getType().hasName("HTTPContext *")
and vh_1235.getType().hasName("URLContext *")
and vread_ret_1238.getType().hasName("int")
and vseek_ret_1239.getType().hasName("int64_t")
and vline_1252.getType().hasName("char[32]")
and vtarget_1276.getType().hasName("int64_t")
and vbuf_1235.getParentScope+() = func
and vsize_1235.getParentScope+() = func
and vs_1237.getParentScope+() = func
and vh_1235.getParentScope+() = func
and vread_ret_1238.getParentScope+() = func
and vseek_ret_1239.getParentScope+() = func
and vline_1252.getParentScope+() = func
and vtarget_1276.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
