/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufResize
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufResize
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-buf.c-xmlBufResize CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="2147483647"
		and not target_1.getValue()="0"
		and target_1.getParent().(MulExpr).getParent().(AddExpr).getAnOperand() instanceof MulExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="2"
		and not target_2.getValue()="1"
		and target_2.getParent().(MulExpr).getParent().(AssignExpr).getRValue() instanceof MulExpr
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="2147483647"
		and not target_3.getValue()="10"
		and target_3.getParent().(MulExpr).getParent().(AddExpr).getAnOperand() instanceof MulExpr
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="2"
		and not target_4.getValue()="1"
		and target_4.getParent().(DivExpr).getParent().(GTExpr).getLesserOperand() instanceof DivExpr
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Parameter vbuf_732, SwitchStmt target_36) {
	exists(EqualityOperation target_5 |
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
		and target_5.getAnOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
		and target_36.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vsize_732, Variable vnewSize_734, RelationalOperation target_37, ExprStmt target_38) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_6.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_732
		and target_6.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="18446744073709551605"
		and target_6.getRValue().(ConditionalExpr).getThen().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_6.getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_732
		and target_6.getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="10"
		and target_37.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getLValue().(VariableAccess).getLocation()))
}

/*predicate func_8(Variable vnewSize_734, BlockStmt target_39) {
	exists(SubExpr target_8 |
		target_8.getValue()="18446744073709551605"
		and target_8.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vnewSize_734
		and target_8.getParent().(GTExpr).getLesserOperand() instanceof DivExpr
		and target_8.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_39)
}

*/
/*predicate func_9(Function func) {
	exists(UnaryMinusExpr target_9 |
		target_9.getValue()="18446744073709551615"
		and target_9.getEnclosingFunction() = func)
}

*/
predicate func_10(Parameter vbuf_732, Variable vnewSize_734, ExprStmt target_41, ExprStmt target_24) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_10.getRValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_10.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
		and target_10.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_41.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_24.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getLValue().(VariableAccess).getLocation()))
}

predicate func_12(Variable vnewSize_734, BlockStmt target_42) {
	exists(DivExpr target_12 |
		target_12.getValue()="9223372036854775807"
		and target_12.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vnewSize_734
		and target_12.getParent().(GTExpr).getLesserOperand() instanceof DivExpr
		and target_12.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_42)
}

predicate func_13(Parameter vsize_732, Variable vnewSize_734, RelationalOperation target_43) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_13.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_732
		and target_13.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="18446744073709551605"
		and target_13.getRValue().(ConditionalExpr).getThen().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_13.getRValue().(ConditionalExpr).getElse() instanceof AddExpr
		and target_43.getLesserOperand().(VariableAccess).getLocation().isBefore(target_13.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_14(Parameter vbuf_732, Parameter vsize_732, Variable vnewSize_734, PointerFieldAccess target_45, RelationalOperation target_17, ExprStmt target_46) {
	exists(IfStmt target_14 |
		target_14.getCondition() instanceof RelationalOperation
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsize_732
		and target_14.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_14.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_14.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
		and target_14.getElse().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_732
		and target_14.getElse().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnewSize_734
		and target_14.getElse().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnewSize_734
		and target_14.getElse().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_14.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_45
		and target_17.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_15(Variable vnewSize_734, BlockStmt target_42, RelationalOperation target_49) {
	exists(RelationalOperation target_15 |
		 (target_15 instanceof GTExpr or target_15 instanceof LTExpr)
		and target_15.getGreaterOperand().(VariableAccess).getTarget()=vnewSize_734
		and target_15.getLesserOperand().(DivExpr).getValue()="9223372036854775807"
		and target_15.getParent().(IfStmt).getThen()=target_42
		and target_49.getLesserOperand().(VariableAccess).getLocation().isBefore(target_15.getGreaterOperand().(VariableAccess).getLocation()))
}

*/
predicate func_16(Parameter vsize_732, Variable vnewSize_734, ExprStmt target_23) {
	exists(AssignExpr target_16 |
		target_16.getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_16.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_732
		and target_16.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="18446744073709551605"
		and target_16.getRValue().(ConditionalExpr).getThen().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_16.getRValue().(ConditionalExpr).getElse() instanceof AddExpr
		and target_23.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getLocation().isBefore(target_16.getLValue().(VariableAccess).getLocation()))
}

predicate func_17(Parameter vbuf_732, RelationalOperation target_17) {
		 (target_17 instanceof GTExpr or target_17 instanceof LTExpr)
		and target_17.getLesserOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_17.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
		and target_17.getGreaterOperand().(Literal).getValue()="4096"
		and target_17.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_18(Parameter vbuf_732, PointerFieldAccess target_18) {
		target_18.getTarget().getName()="size"
		and target_18.getQualifier().(VariableAccess).getTarget()=vbuf_732
}

predicate func_19(Parameter vbuf_732, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="size"
		and target_19.getQualifier().(VariableAccess).getTarget()=vbuf_732
}

predicate func_20(Parameter vsize_732, Variable vnewSize_734, AddExpr target_20) {
		target_20.getAnOperand().(VariableAccess).getTarget()=vsize_732
		and target_20.getAnOperand().(Literal).getValue()="10"
		and target_20.getParent().(AssignExpr).getRValue() = target_20
		and target_20.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_734
}

predicate func_21(Parameter vbuf_732, PointerFieldAccess target_21) {
		target_21.getTarget().getName()="size"
		and target_21.getQualifier().(VariableAccess).getTarget()=vbuf_732
}

predicate func_22(Parameter vsize_732, Variable vnewSize_734, AddExpr target_22) {
		target_22.getAnOperand().(VariableAccess).getTarget()=vsize_732
		and target_22.getAnOperand().(Literal).getValue()="10"
		and target_22.getParent().(AssignExpr).getRValue() = target_22
		and target_22.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_734
}

predicate func_23(Variable vnewSize_734, ExprStmt target_23) {
		target_23.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_23.getExpr().(AssignMulExpr).getRValue().(Literal).getValue()="2"
}

predicate func_24(Variable vnewSize_734, ExprStmt target_24) {
		target_24.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_24.getExpr().(AssignMulExpr).getRValue().(Literal).getValue()="2"
}

predicate func_27(Parameter vbuf_732, Parameter vsize_732, Variable vnewSize_734, AssignExpr target_27) {
		target_27.getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_27.getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="size"
		and target_27.getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
		and target_27.getRValue().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_27.getRValue().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
		and target_27.getRValue().(ConditionalExpr).getThen().(MulExpr).getRightOperand() instanceof Literal
		and target_27.getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_732
		and target_27.getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="10"
}

/*predicate func_28(Parameter vbuf_732, ExprStmt target_41, MulExpr target_28) {
		target_28.getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_28.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
		and target_28.getRightOperand() instanceof Literal
		and target_28.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_41.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

*/
predicate func_29(Variable vnewSize_734, BlockStmt target_39, RelationalOperation target_37, ExprStmt target_23, VariableAccess target_29) {
		target_29.getTarget()=vnewSize_734
		and target_29.getParent().(GTExpr).getLesserOperand().(DivExpr).getValue()="2147483647"
		and target_29.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_39
		and target_37.getLesserOperand().(VariableAccess).getLocation().isBefore(target_29.getLocation())
		and target_29.getLocation().isBefore(target_23.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getLocation())
}

/*predicate func_30(Variable vnewSize_734, BlockStmt target_39, RelationalOperation target_37, ExprStmt target_23, DivExpr target_30) {
		target_30.getValue()="2147483647"
		and target_30.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vnewSize_734
		and target_30.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_39
		and target_37.getLesserOperand().(VariableAccess).getLocation().isBefore(target_30.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getLocation())
		and target_30.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_23.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_31(Variable vnewSize_734, AssignExpr target_31) {
		target_31.getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_31.getRValue() instanceof AddExpr
}

predicate func_32(Parameter vbuf_732, Variable vnewSize_734, AssignExpr target_32) {
		target_32.getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_32.getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_32.getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
		and target_32.getRValue().(MulExpr).getRightOperand() instanceof Literal
}

predicate func_33(Variable vnewSize_734, BlockStmt target_42, ExprStmt target_24, VariableAccess target_33) {
		target_33.getTarget()=vnewSize_734
		and target_33.getParent().(GTExpr).getLesserOperand().(DivExpr).getValue()="2147483647"
		and target_33.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_42
		and target_33.getLocation().isBefore(target_24.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getLocation())
}

/*predicate func_34(Variable vnewSize_734, BlockStmt target_42, ExprStmt target_24, DivExpr target_34) {
		target_34.getValue()="2147483647"
		and target_34.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vnewSize_734
		and target_34.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_42
		and target_34.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_24.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_35(Variable vnewSize_734, RelationalOperation target_51, AssignExpr target_35) {
		target_35.getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_35.getRValue() instanceof AddExpr
		and target_35.getLValue().(VariableAccess).getLocation().isBefore(target_51.getLesserOperand().(VariableAccess).getLocation())
}

predicate func_36(Parameter vbuf_732, Parameter vsize_732, Variable vnewSize_734, SwitchStmt target_36) {
		target_36.getExpr().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_36.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
		and target_36.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr() instanceof AssignExpr
		and target_36.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_732
		and target_36.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnewSize_734
		and target_36.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnewSize_734
		and target_36.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof DivExpr
		and target_36.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
}

predicate func_37(Parameter vsize_732, Variable vnewSize_734, RelationalOperation target_37) {
		 (target_37 instanceof GTExpr or target_37 instanceof LTExpr)
		and target_37.getGreaterOperand().(VariableAccess).getTarget()=vsize_732
		and target_37.getLesserOperand().(VariableAccess).getTarget()=vnewSize_734
}

predicate func_38(Parameter vsize_732, Variable vnewSize_734, ExprStmt target_38) {
		target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_734
		and target_38.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsize_732
}

predicate func_39(Parameter vbuf_732, BlockStmt target_39) {
		target_39.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlBufMemoryError")
		and target_39.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_732
		and target_39.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="growing buffer"
		and target_39.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_41(Parameter vbuf_732, ExprStmt target_41) {
		target_41.getExpr().(FunctionCall).getTarget().hasName("xmlBufMemoryError")
		and target_41.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_732
		and target_41.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="growing buffer"
}

predicate func_42(Parameter vbuf_732, BlockStmt target_42) {
		target_42.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlBufMemoryError")
		and target_42.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_732
		and target_42.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="growing buffer"
		and target_42.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_43(Parameter vbuf_732, Parameter vsize_732, RelationalOperation target_43) {
		 (target_43 instanceof GTExpr or target_43 instanceof LTExpr)
		and target_43.getLesserOperand().(VariableAccess).getTarget()=vsize_732
		and target_43.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_43.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_732
}

predicate func_45(Parameter vbuf_732, PointerFieldAccess target_45) {
		target_45.getTarget().getName()="alloc"
		and target_45.getQualifier().(VariableAccess).getTarget()=vbuf_732
}

predicate func_46(Parameter vbuf_732, ExprStmt target_46) {
		target_46.getExpr().(FunctionCall).getTarget().hasName("xmlBufMemoryError")
		and target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_732
		and target_46.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="growing buffer"
}

predicate func_49(Parameter vsize_732, Variable vnewSize_734, RelationalOperation target_49) {
		 (target_49 instanceof GTExpr or target_49 instanceof LTExpr)
		and target_49.getGreaterOperand().(VariableAccess).getTarget()=vsize_732
		and target_49.getLesserOperand().(VariableAccess).getTarget()=vnewSize_734
}

predicate func_51(Variable vnewSize_734, RelationalOperation target_51) {
		 (target_51 instanceof GTExpr or target_51 instanceof LTExpr)
		and target_51.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_51.getLesserOperand().(VariableAccess).getTarget()=vnewSize_734
}

from Function func, Parameter vbuf_732, Parameter vsize_732, Variable vnewSize_734, Literal target_1, Literal target_2, Literal target_3, Literal target_4, RelationalOperation target_17, PointerFieldAccess target_18, PointerFieldAccess target_19, AddExpr target_20, PointerFieldAccess target_21, AddExpr target_22, ExprStmt target_23, ExprStmt target_24, AssignExpr target_27, VariableAccess target_29, AssignExpr target_31, AssignExpr target_32, VariableAccess target_33, AssignExpr target_35, SwitchStmt target_36, RelationalOperation target_37, ExprStmt target_38, BlockStmt target_39, ExprStmt target_41, BlockStmt target_42, RelationalOperation target_43, PointerFieldAccess target_45, ExprStmt target_46, RelationalOperation target_49, RelationalOperation target_51
where
func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and not func_5(vbuf_732, target_36)
and not func_6(vsize_732, vnewSize_734, target_37, target_38)
and not func_10(vbuf_732, vnewSize_734, target_41, target_24)
and not func_12(vnewSize_734, target_42)
and not func_13(vsize_732, vnewSize_734, target_43)
and not func_14(vbuf_732, vsize_732, vnewSize_734, target_45, target_17, target_46)
and not func_16(vsize_732, vnewSize_734, target_23)
and func_17(vbuf_732, target_17)
and func_18(vbuf_732, target_18)
and func_19(vbuf_732, target_19)
and func_20(vsize_732, vnewSize_734, target_20)
and func_21(vbuf_732, target_21)
and func_22(vsize_732, vnewSize_734, target_22)
and func_23(vnewSize_734, target_23)
and func_24(vnewSize_734, target_24)
and func_27(vbuf_732, vsize_732, vnewSize_734, target_27)
and func_29(vnewSize_734, target_39, target_37, target_23, target_29)
and func_31(vnewSize_734, target_31)
and func_32(vbuf_732, vnewSize_734, target_32)
and func_33(vnewSize_734, target_42, target_24, target_33)
and func_35(vnewSize_734, target_51, target_35)
and func_36(vbuf_732, vsize_732, vnewSize_734, target_36)
and func_37(vsize_732, vnewSize_734, target_37)
and func_38(vsize_732, vnewSize_734, target_38)
and func_39(vbuf_732, target_39)
and func_41(vbuf_732, target_41)
and func_42(vbuf_732, target_42)
and func_43(vbuf_732, vsize_732, target_43)
and func_45(vbuf_732, target_45)
and func_46(vbuf_732, target_46)
and func_49(vsize_732, vnewSize_734, target_49)
and func_51(vnewSize_734, target_51)
and vbuf_732.getType().hasName("xmlBufPtr")
and vsize_732.getType().hasName("size_t")
and vnewSize_734.getType().hasName("unsigned int")
and vbuf_732.getFunction() = func
and vsize_732.getFunction() = func
and vnewSize_734.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
