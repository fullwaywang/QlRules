/**
 * @name libxml2-932cc9896ab41475d4aa429c27d9afd175959d74-xmlSnprintfElementContent
 * @id cpp/libxml2/932cc9896ab41475d4aa429c27d9afd175959d74/xmlSnprintfElementContent
 * @description libxml2-932cc9896ab41475d4aa429c27d9afd175959d74-valid.c-xmlSnprintfElementContent CVE-2017-9047
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcontent_1250, EqualityOperation target_13, ExprStmt target_14, Literal target_0) {
		target_0.getValue()="10"
		and not target_0.getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_0.getParent().(AddExpr).getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="prefix"
		and target_0.getParent().(AddExpr).getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(AddExpr).getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getParent().(AddExpr).getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Parameter vcontent_1250, EqualityOperation target_13, ExprStmt target_14) {
	exists(AssignAddExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_1.getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="prefix"
		and target_1.getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
		and target_1.getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vcontent_1250, BlockStmt target_15, ExprStmt target_14, RelationalOperation target_11) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="prefix"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
		and target_3.getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen()=target_15
		and target_14.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vsize_1250, Parameter vbuf_1250, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_1250
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1250
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_4.getThen() instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_4)
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_5(Parameter vsize_1250, Parameter vcontent_1250, Variable vlen_1251, BlockStmt target_15, SubExpr target_5) {
		target_5.getLeftOperand().(VariableAccess).getTarget()=vsize_1250
		and target_5.getRightOperand().(VariableAccess).getTarget()=vlen_1251
		and target_5.getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_5.getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_5.getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
		and target_5.getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="10"
		and target_5.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_15
}

predicate func_6(Parameter vcontent_1250, Parameter vbuf_1250, PointerFieldAccess target_19, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_6.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strcat")
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1250
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
		and target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_19
}

/*predicate func_7(Parameter vcontent_1250, FunctionCall target_7) {
		target_7.getTarget().hasName("xmlStrlen")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
}

*/
predicate func_8(Parameter vbuf_1250, VariableAccess target_8) {
		target_8.getTarget()=vbuf_1250
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_9(PointerFieldAccess target_19, Function func, BreakStmt target_9) {
		target_9.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_19
		and target_9.getEnclosingFunction() = func
}

predicate func_10(RelationalOperation target_11, Function func, ReturnStmt target_10) {
		target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_10.getEnclosingFunction() = func
}

predicate func_11(BlockStmt target_15, Function func, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand() instanceof SubExpr
		and target_11.getGreaterOperand().(AddExpr).getAnOperand() instanceof FunctionCall
		and target_11.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="10"
		and target_11.getParent().(IfStmt).getThen()=target_15
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Parameter vbuf_1250, ExprStmt target_17, ExprStmt target_18, FunctionCall target_12) {
		target_12.getTarget().hasName("strcat")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vbuf_1250
		and target_12.getArgument(1).(StringLiteral).getValue()=" ..."
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getArgument(0).(VariableAccess).getLocation())
		and target_12.getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_13(Parameter vcontent_1250, EqualityOperation target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="prefix"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Parameter vcontent_1250, Parameter vbuf_1250, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("strcat")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1250
		and target_14.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="prefix"
		and target_14.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
}

predicate func_15(BlockStmt target_15) {
		target_15.getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_15.getStmt(1) instanceof ReturnStmt
}

predicate func_16(Parameter vsize_1250, Parameter vcontent_1250, Parameter vbuf_1250, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("xmlSnprintfElementContent")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1250
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsize_1250
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="c2"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
		and target_16.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_17(Parameter vbuf_1250, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("strcat")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1250
		and target_17.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=":"
}

predicate func_18(Parameter vcontent_1250, Parameter vbuf_1250, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("strcat")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1250
		and target_18.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_18.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1250
}

predicate func_19(Parameter vcontent_1250, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="type"
		and target_19.getQualifier().(VariableAccess).getTarget()=vcontent_1250
}

from Function func, Parameter vsize_1250, Parameter vcontent_1250, Variable vlen_1251, Parameter vbuf_1250, Literal target_0, SubExpr target_5, IfStmt target_6, VariableAccess target_8, BreakStmt target_9, ReturnStmt target_10, RelationalOperation target_11, FunctionCall target_12, EqualityOperation target_13, ExprStmt target_14, BlockStmt target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, PointerFieldAccess target_19
where
func_0(vcontent_1250, target_13, target_14, target_0)
and not func_1(vcontent_1250, target_13, target_14)
and not func_3(vcontent_1250, target_15, target_14, target_11)
and not func_4(vsize_1250, vbuf_1250, target_16, target_17, target_18, func)
and func_5(vsize_1250, vcontent_1250, vlen_1251, target_15, target_5)
and func_6(vcontent_1250, vbuf_1250, target_19, target_6)
and func_8(vbuf_1250, target_8)
and func_9(target_19, func, target_9)
and func_10(target_11, func, target_10)
and func_11(target_15, func, target_11)
and func_12(vbuf_1250, target_17, target_18, target_12)
and func_13(vcontent_1250, target_13)
and func_14(vcontent_1250, vbuf_1250, target_14)
and func_15(target_15)
and func_16(vsize_1250, vcontent_1250, vbuf_1250, target_16)
and func_17(vbuf_1250, target_17)
and func_18(vcontent_1250, vbuf_1250, target_18)
and func_19(vcontent_1250, target_19)
and vsize_1250.getType().hasName("int")
and vcontent_1250.getType().hasName("xmlElementContentPtr")
and vlen_1251.getType().hasName("int")
and vbuf_1250.getType().hasName("char *")
and vsize_1250.getFunction() = func
and vcontent_1250.getFunction() = func
and vlen_1251.(LocalVariable).getFunction() = func
and vbuf_1250.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
