/**
 * @name varnish-515a93df894430767073ccd8265497b6b25b54b5-h2h_addhdr
 * @id cpp/varnish/515a93df894430767073ccd8265497b6b25b54b5/h2h-addhdr
 * @description varnish-515a93df894430767073ccd8265497b6b25b54b5-bin/varnishd/http2/cache_http2_hpack.c-h2h_addhdr CVE-2022-45060
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(NotExpr target_8, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vb_95, Parameter vlen_95, NotExpr target_8, ExprStmt target_9, NotExpr target_10, ExprStmt target_11, ExprStmt target_12) {
	exists(ForStmt target_2 |
		target_2.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_2.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(VariableAccess).getTarget()=vb_95
		and target_2.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_95
		and target_2.getUpdate().(CommaExpr).getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_2.getUpdate().(CommaExpr).getRightOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="1"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="4"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getType().hasName("const h2_error_s[1]")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_2.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_10.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_11.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_3(NotExpr target_10, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vb_95, Parameter vlen_95, NotExpr target_10, ExprStmt target_13, NotExpr target_14, ExprStmt target_12, ExprStmt target_15) {
	exists(ForStmt target_4 |
		target_4.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_4.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(VariableAccess).getTarget()=vb_95
		and target_4.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_4.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_95
		and target_4.getUpdate().(CommaExpr).getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_4.getUpdate().(CommaExpr).getRightOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(BitwiseOrExpr).getValue()="3"
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="4"
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getType().hasName("const h2_error_s[1]")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_13.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_4.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_14.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_12.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vb_95, Parameter vnamelen_95, Parameter vlen_95, NotExpr target_14, ExprStmt target_16, NotExpr target_17, ExprStmt target_15, ExprStmt target_18) {
	exists(ForStmt target_5 |
		target_5.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_5.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vb_95
		and target_5.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vnamelen_95
		and target_5.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_5.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_95
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vnamelen_95
		and target_5.getUpdate().(CommaExpr).getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_5.getUpdate().(CommaExpr).getRightOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="1"
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="4"
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getType().hasName("const h2_error_s[1]")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_16.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_5.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_17.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_15.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_6(NotExpr target_14, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_6.getThen().(ReturnStmt).getExpr().(VariableAccess).getType().hasName("const h2_error_s[1]")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vhp_95, Parameter vnamelen_95, Variable vb0_98, Variable vn_99, ExprStmt target_19, ArrayExpr target_20, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pdiff")
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="b"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_99
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="e"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_99
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_95
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Empty pseudo-header %.*s"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnamelen_95
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vb0_98
		and target_7.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("const h2_error_s[1]")
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_7)
		and target_19.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_20.getArrayOffset().(VariableAccess).getLocation().isBefore(target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vb_95, Parameter vnamelen_95, NotExpr target_8) {
		target_8.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_8.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_95
		and target_8.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=":method: "
		and target_8.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnamelen_95
}

predicate func_9(Parameter vb_95, Parameter vnamelen_95, ExprStmt target_9) {
		target_9.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vb_95
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vnamelen_95
}

predicate func_10(Parameter vb_95, Parameter vnamelen_95, NotExpr target_10) {
		target_10.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_10.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_95
		and target_10.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=":path: "
		and target_10.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnamelen_95
}

predicate func_11(Parameter vnamelen_95, Parameter vlen_95, ExprStmt target_11) {
		target_11.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_95
		and target_11.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vnamelen_95
}

predicate func_12(Parameter vnamelen_95, Parameter vlen_95, ExprStmt target_12) {
		target_12.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_95
		and target_12.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vnamelen_95
}

predicate func_13(Parameter vb_95, Parameter vnamelen_95, ExprStmt target_13) {
		target_13.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vb_95
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vnamelen_95
}

predicate func_14(Parameter vb_95, Parameter vnamelen_95, NotExpr target_14) {
		target_14.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_14.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_95
		and target_14.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=":scheme: "
		and target_14.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnamelen_95
}

predicate func_15(Parameter vlen_95, ExprStmt target_15) {
		target_15.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_95
		and target_15.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="1"
}

predicate func_16(Parameter vb_95, ExprStmt target_16) {
		target_16.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vb_95
}

predicate func_17(Parameter vb_95, Parameter vnamelen_95, NotExpr target_17) {
		target_17.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_17.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_95
		and target_17.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=":authority: "
		and target_17.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnamelen_95
}

predicate func_18(Parameter vlen_95, ExprStmt target_18) {
		target_18.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_95
		and target_18.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="6"
}

predicate func_19(Parameter vhp_95, Parameter vb_95, Parameter vnamelen_95, Parameter vlen_95, Variable vb0_98, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_19.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_19.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_95
		and target_19.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Duplicate pseudo-header %.*s%.*s"
		and target_19.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnamelen_95
		and target_19.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vb0_98
		and target_19.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_95
		and target_19.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="20"
		and target_19.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(Literal).getValue()="20"
		and target_19.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(VariableAccess).getTarget()=vlen_95
		and target_19.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vb_95
}

predicate func_20(Parameter vhp_95, Variable vn_99, ArrayExpr target_20) {
		target_20.getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_20.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_95
		and target_20.getArrayOffset().(VariableAccess).getTarget()=vn_99
}

from Function func, Parameter vhp_95, Parameter vb_95, Parameter vnamelen_95, Parameter vlen_95, Variable vb0_98, Variable vn_99, NotExpr target_8, ExprStmt target_9, NotExpr target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, NotExpr target_14, ExprStmt target_15, ExprStmt target_16, NotExpr target_17, ExprStmt target_18, ExprStmt target_19, ArrayExpr target_20
where
not func_0(func)
and not func_1(target_8, func)
and not func_2(vb_95, vlen_95, target_8, target_9, target_10, target_11, target_12)
and not func_3(target_10, func)
and not func_4(vb_95, vlen_95, target_10, target_13, target_14, target_12, target_15)
and not func_5(vb_95, vnamelen_95, vlen_95, target_14, target_16, target_17, target_15, target_18)
and not func_6(target_14, func)
and not func_7(vhp_95, vnamelen_95, vb0_98, vn_99, target_19, target_20, func)
and func_8(vb_95, vnamelen_95, target_8)
and func_9(vb_95, vnamelen_95, target_9)
and func_10(vb_95, vnamelen_95, target_10)
and func_11(vnamelen_95, vlen_95, target_11)
and func_12(vnamelen_95, vlen_95, target_12)
and func_13(vb_95, vnamelen_95, target_13)
and func_14(vb_95, vnamelen_95, target_14)
and func_15(vlen_95, target_15)
and func_16(vb_95, target_16)
and func_17(vb_95, vnamelen_95, target_17)
and func_18(vlen_95, target_18)
and func_19(vhp_95, vb_95, vnamelen_95, vlen_95, vb0_98, target_19)
and func_20(vhp_95, vn_99, target_20)
and vhp_95.getType().hasName("http *")
and vb_95.getType().hasName("char *")
and vnamelen_95.getType().hasName("size_t")
and vlen_95.getType().hasName("size_t")
and vb0_98.getType().hasName("const char *")
and vn_99.getType().hasName("unsigned int")
and vhp_95.getParentScope+() = func
and vb_95.getParentScope+() = func
and vnamelen_95.getParentScope+() = func
and vlen_95.getParentScope+() = func
and vb0_98.getParentScope+() = func
and vn_99.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
