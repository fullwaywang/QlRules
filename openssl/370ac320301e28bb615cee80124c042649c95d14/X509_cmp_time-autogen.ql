/**
 * @name openssl-370ac320301e28bb615cee80124c042649c95d14-X509_cmp_time
 * @id cpp/openssl/370ac320301e28bb615cee80124c042649c95d14/X509-cmp-time
 * @description openssl-370ac320301e28bb615cee80124c042649c95d14-crypto/x509/x509_vfy.c-X509_cmp_time CVE-2015-1789
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_1640, VariableAccess target_0) {
		target_0.getTarget()=vi_1640
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="length"
}

/*predicate func_1(Variable vi_1640, VariableAccess target_1) {
		target_1.getTarget()=vi_1640
}

*/
predicate func_2(Variable vi_1640, ExprStmt target_38, Literal target_2) {
		target_2.getValue()="11"
		and not target_2.getValue()="2"
		and target_2.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1640
		and target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
}

/*predicate func_3(Variable vi_1640, ReturnStmt target_39, VariableAccess target_3) {
		target_3.getTarget()=vi_1640
		and target_3.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="13"
		and target_3.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_39
}

*/
/*predicate func_4(Variable vi_1640, LogicalOrExpr target_40, Literal target_4) {
		target_4.getValue()="13"
		and not target_4.getValue()="2"
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1640
		and target_40.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
}

*/
predicate func_5(Variable vi_1640, RelationalOperation target_41, Literal target_5) {
		target_5.getValue()="17"
		and not target_5.getValue()="1"
		and target_5.getParent().(GTExpr).getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_1640
		and target_5.getParent().(GTExpr).getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_41.getLesserOperand().(VariableAccess).getLocation())
}

predicate func_7(Variable vi_1640, ReturnStmt target_42) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_7.getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1640
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_1640
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_7.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_42)
}

predicate func_10(Function func) {
	exists(AssignSubExpr target_10 |
		target_10.getLValue().(VariableAccess).getType().hasName("int")
		and target_10.getRValue().(Literal).getValue()="10"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(BlockStmt target_43, Function func) {
	exists(LogicalOrExpr target_11 |
		target_11.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_11.getParent().(IfStmt).getThen()=target_43
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(EqualityOperation target_44, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_12.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="12"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(6)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(RelationalOperation target_41, Function func) {
	exists(ReturnStmt target_13 |
		target_13.getExpr().(Literal).getValue()="0"
		and target_13.getParent().(IfStmt).getCondition()=target_41
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(LogicalOrExpr target_21, Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_14.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="2"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_14
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_14.getEnclosingFunction() = func)
}

predicate func_16(EqualityOperation target_29, Function func) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_16
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_29
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(Variable vi_1640, EqualityOperation target_24, RelationalOperation target_41) {
	exists(ForStmt target_17 |
		target_17.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_1640
		and target_17.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_17.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1640
		and target_17.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="3"
		and target_17.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_17.getUpdate().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_1640
		and target_17.getUpdate().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand() instanceof PostfixIncrExpr
		and target_17.getUpdate().(CommaExpr).getRightOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerDereferenceExpr
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof CharLiteral
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerDereferenceExpr
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof CharLiteral
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_17
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_41.getLesserOperand().(VariableAccess).getLocation().isBefore(target_17.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_18(EqualityOperation target_24, Function func) {
	exists(LabelStmt target_18 |
		target_18.toString() = "label ...:"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_18
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Function func) {
	exists(IfStmt target_19 |
		target_19.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_19.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_19 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_19))
}

predicate func_20(Variable vstr_1636, EqualityOperation target_24, Function func) {
	exists(IfStmt target_20 |
		target_20.getCondition() instanceof EqualityOperation
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_20.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_20.getElse().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_20.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_20.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="5"
		and target_20.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_20.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(CharLiteral).getValue()="48"
		and target_20.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstr_1636
		and target_20.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
		and target_20.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(CharLiteral).getValue()="57"
		and target_20.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_20.getElse().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_20.getElse().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_20.getElse().(BlockStmt).getStmt(5) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_20 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_20)
		and target_20.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_24.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_21(Variable vstr_1636, BlockStmt target_43, LogicalOrExpr target_21) {
		target_21.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstr_1636
		and target_21.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="90"
		and target_21.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstr_1636
		and target_21.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstr_1636
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="43"
		and target_21.getParent().(IfStmt).getThen()=target_43
}

predicate func_22(Variable vstr_1636, PointerDereferenceExpr target_22) {
		target_22.getOperand().(VariableAccess).getTarget()=vstr_1636
}

predicate func_23(Variable vstr_1636, PointerDereferenceExpr target_23) {
		target_23.getOperand().(VariableAccess).getTarget()=vstr_1636
}

predicate func_24(Variable vstr_1636, ExprStmt target_31, EqualityOperation target_24) {
		target_24.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstr_1636
		and target_24.getAnOperand().(CharLiteral).getValue()="90"
		and target_24.getParent().(IfStmt).getThen()=target_31
}

predicate func_25(Variable vstr_1636, EqualityOperation target_24, IfStmt target_25) {
		target_25.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstr_1636
		and target_25.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="43"
		and target_25.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstr_1636
		and target_25.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_25.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_26(Variable vstr_1636, Variable voffset_1638, EqualityOperation target_24, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_1638
		and target_26.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(CharLiteral).getValue()="48"
		and target_26.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="10"
		and target_26.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstr_1636
		and target_26.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_26.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(CharLiteral).getValue()="48"
		and target_26.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="60"
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_27(Variable vstr_1636, Variable voffset_1638, EqualityOperation target_24, ExprStmt target_27) {
		target_27.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_1638
		and target_27.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstr_1636
		and target_27.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_27.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(CharLiteral).getValue()="48"
		and target_27.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="10"
		and target_27.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstr_1636
		and target_27.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
		and target_27.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(CharLiteral).getValue()="48"
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_28(Variable vstr_1636, Variable voffset_1638, EqualityOperation target_24, IfStmt target_28) {
		target_28.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstr_1636
		and target_28.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_28.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_1638
		and target_28.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=voffset_1638
		and target_28.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_29(Variable vstr_1636, BlockStmt target_45, EqualityOperation target_29) {
		target_29.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstr_1636
		and target_29.getAnOperand().(CharLiteral).getValue()="46"
		and target_29.getParent().(IfStmt).getThen()=target_45
}

predicate func_30(Variable vstr_1636, PostfixIncrExpr target_30) {
		target_30.getOperand().(VariableAccess).getTarget()=vstr_1636
}

predicate func_31(Variable voffset_1638, EqualityOperation target_24, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_1638
		and target_31.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_31.getParent().(IfStmt).getCondition()=target_24
}

predicate func_34(Variable vi_1640, VariableAccess target_34) {
		target_34.getTarget()=vi_1640
}

predicate func_35(EqualityOperation target_29, Function func, WhileStmt target_35) {
		target_35.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerDereferenceExpr
		and target_35.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof CharLiteral
		and target_35.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerDereferenceExpr
		and target_35.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof CharLiteral
		and target_35.getStmt().(ExprStmt).getExpr() instanceof PostfixIncrExpr
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_29
		and target_35.getEnclosingFunction() = func
}

/*predicate func_36(Function func, RelationalOperation target_36) {
		 (target_36 instanceof GEExpr or target_36 instanceof LEExpr)
		and target_36.getGreaterOperand() instanceof PointerDereferenceExpr
		and target_36.getLesserOperand() instanceof CharLiteral
		and target_36.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerDereferenceExpr
		and target_36.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof CharLiteral
		and target_36.getEnclosingFunction() = func
}

*/
/*predicate func_37(Function func, RelationalOperation target_37) {
		 (target_37 instanceof GEExpr or target_37 instanceof LEExpr)
		and target_37.getLesserOperand() instanceof PointerDereferenceExpr
		and target_37.getGreaterOperand() instanceof CharLiteral
		and target_37.getEnclosingFunction() = func
}

*/
predicate func_38(Variable vi_1640, ExprStmt target_38) {
		target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_1640
		and target_38.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="length"
}

predicate func_39(ReturnStmt target_39) {
		target_39.getExpr().(Literal).getValue()="0"
}

predicate func_40(Variable vi_1640, LogicalOrExpr target_40) {
		target_40.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1640
		and target_40.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_40.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_1640
		and target_40.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
}

predicate func_41(Variable vi_1640, RelationalOperation target_41) {
		 (target_41 instanceof GTExpr or target_41 instanceof LTExpr)
		and target_41.getLesserOperand().(VariableAccess).getTarget()=vi_1640
		and target_41.getGreaterOperand() instanceof Literal
}

predicate func_42(ReturnStmt target_42) {
		target_42.getExpr().(Literal).getValue()="0"
}

predicate func_43(BlockStmt target_43) {
		target_43.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="48"
		and target_43.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="48"
}

predicate func_44(EqualityOperation target_44) {
		target_44.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_44.getAnOperand().(Literal).getValue()="23"
}

predicate func_45(Variable vstr_1636, BlockStmt target_45) {
		target_45.getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstr_1636
		and target_45.getStmt(1) instanceof WhileStmt
}

from Function func, Variable vstr_1636, Variable voffset_1638, Variable vi_1640, VariableAccess target_0, Literal target_2, Literal target_5, LogicalOrExpr target_21, PointerDereferenceExpr target_22, PointerDereferenceExpr target_23, EqualityOperation target_24, IfStmt target_25, ExprStmt target_26, ExprStmt target_27, IfStmt target_28, EqualityOperation target_29, PostfixIncrExpr target_30, ExprStmt target_31, VariableAccess target_34, WhileStmt target_35, ExprStmt target_38, ReturnStmt target_39, LogicalOrExpr target_40, RelationalOperation target_41, ReturnStmt target_42, BlockStmt target_43, EqualityOperation target_44, BlockStmt target_45
where
func_0(vi_1640, target_0)
and func_2(vi_1640, target_38, target_2)
and func_5(vi_1640, target_41, target_5)
and not func_7(vi_1640, target_42)
and not func_10(func)
and not func_11(target_43, func)
and not func_12(target_44, func)
and not func_13(target_41, func)
and not func_14(target_21, func)
and not func_16(target_29, func)
and not func_17(vi_1640, target_24, target_41)
and not func_18(target_24, func)
and not func_19(func)
and not func_20(vstr_1636, target_24, func)
and func_21(vstr_1636, target_43, target_21)
and func_22(vstr_1636, target_22)
and func_23(vstr_1636, target_23)
and func_24(vstr_1636, target_31, target_24)
and func_25(vstr_1636, target_24, target_25)
and func_26(vstr_1636, voffset_1638, target_24, target_26)
and func_27(vstr_1636, voffset_1638, target_24, target_27)
and func_28(vstr_1636, voffset_1638, target_24, target_28)
and func_29(vstr_1636, target_45, target_29)
and func_30(vstr_1636, target_30)
and func_31(voffset_1638, target_24, target_31)
and func_34(vi_1640, target_34)
and func_35(target_29, func, target_35)
and func_38(vi_1640, target_38)
and func_39(target_39)
and func_40(vi_1640, target_40)
and func_41(vi_1640, target_41)
and func_42(target_42)
and func_43(target_43)
and func_44(target_44)
and func_45(vstr_1636, target_45)
and vstr_1636.getType().hasName("char *")
and voffset_1638.getType().hasName("long")
and vi_1640.getType().hasName("int")
and vstr_1636.getParentScope+() = func
and voffset_1638.getParentScope+() = func
and vi_1640.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
