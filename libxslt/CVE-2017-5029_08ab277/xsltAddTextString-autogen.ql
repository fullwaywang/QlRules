/**
 * @name libxslt-08ab2774b870de1c7b5a48693df75e8154addae5-xsltAddTextString
 * @id cpp/libxslt/08ab2774b870de1c7b5a48693df75e8154addae5/xsltAddTextString
 * @description libxslt-08ab2774b870de1c7b5a48693df75e8154addae5-libxslt/transform.c-xsltAddTextString CVE-2017-5029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="2147483647"
		and target_0.getParent().(AssignMulExpr).getParent().(ExprStmt).getExpr() instanceof AssignMulExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vctxt_807, BlockStmt target_23, RelationalOperation target_24) {
	exists(SubExpr target_1 |
		target_1.getLeftOperand().(Literal).getValue()="2147483647"
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="lasttuse"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_1.getParent().(GEExpr).getGreaterOperand() instanceof AddExpr
		and target_1.getParent().(GEExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="lasttsize"
		and target_1.getParent().(GEExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_23
		and target_24.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vctxt_807, Parameter vtarget_807, RelationalOperation target_24, EqualityOperation target_26, ExprStmt target_9) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("xsltTransformError")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctxt_807
		and target_2.getArgument(1).(Literal).getValue()="0"
		and target_2.getArgument(2).(VariableAccess).getTarget()=vtarget_807
		and target_2.getArgument(3).(StringLiteral).getValue()="xsltCopyText: text allocation failed\n"
		and target_24.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation())
		and target_26.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(2).(VariableAccess).getLocation())
		and target_2.getArgument(2).(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(RelationalOperation target_24, Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Variable vsize_819) {
	exists(AddExpr target_5 |
		target_5.getAnOperand() instanceof AddExpr
		and target_5.getAnOperand().(Literal).getValue()="1"
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_819)
}

predicate func_6(Parameter vctxt_807, Variable vsize_819, EqualityOperation target_26, ExprStmt target_27, ExprStmt target_9) {
	exists(IfStmt target_6 |
		target_6.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="lasttsize"
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="100"
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getType().hasName("int")
		and target_6.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_6.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_6.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="lasttsize"
		and target_6.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_6.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_819
		and target_6.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_6.getThen().(BlockStmt).getStmt(4).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_819
		and target_6.getThen().(BlockStmt).getStmt(5) instanceof ExprStmt
		and target_6.getThen().(BlockStmt).getStmt(6) instanceof IfStmt
		and target_6.getThen().(BlockStmt).getStmt(7) instanceof ExprStmt
		and target_6.getThen().(BlockStmt).getStmt(8) instanceof ExprStmt
		and target_6.getThen().(BlockStmt).getStmt(9) instanceof ExprStmt
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_7(RelationalOperation target_24, Function func, DeclStmt target_7) {
		target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_7.getEnclosingFunction() = func
}

predicate func_8(RelationalOperation target_24, Function func, DeclStmt target_8) {
		target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Parameter vtarget_807, Variable vnewbuf_818, Variable vsize_819, Variable vxmlRealloc, RelationalOperation target_24, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewbuf_818
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlRealloc
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="content"
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_807
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vsize_819
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_10(Parameter vctxt_807, Parameter vtarget_807, Variable vnewbuf_818, RelationalOperation target_24, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnewbuf_818
		and target_10.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xsltTransformError")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_807
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtarget_807
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="xsltCopyText: text allocation failed\n"
		and target_10.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_11(Parameter vctxt_807, Variable vnewbuf_818, RelationalOperation target_24, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lasttext"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnewbuf_818
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_12(Parameter vtarget_807, Variable vnewbuf_818, RelationalOperation target_24, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_807
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnewbuf_818
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

/*predicate func_13(Parameter vctxt_807, Parameter vlen_808, BlockStmt target_23, AddExpr target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="lasttuse"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_13.getAnOperand().(VariableAccess).getTarget()=vlen_808
		and target_13.getParent().(GEExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="lasttsize"
		and target_13.getParent().(GEExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_13.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_23
}

*/
/*predicate func_14(Parameter vctxt_807, Parameter vlen_808, BlockStmt target_23, PointerFieldAccess target_14) {
		target_14.getTarget().getName()="lasttsize"
		and target_14.getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_14.getParent().(GEExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lasttuse"
		and target_14.getParent().(GEExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_14.getParent().(GEExpr).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_808
		and target_14.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_23
}

*/
predicate func_15(Parameter vctxt_807, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="lasttsize"
		and target_15.getQualifier().(VariableAccess).getTarget()=vctxt_807
}

predicate func_16(Parameter vctxt_807, Variable vsize_819, RelationalOperation target_24, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lasttsize"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsize_819
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_17(Variable vsize_819, VariableAccess target_17) {
		target_17.getTarget()=vsize_819
		and target_17.getParent().(AssignExpr).getLValue() = target_17
		and target_17.getParent().(AssignExpr).getRValue() instanceof AddExpr
}

predicate func_18(Variable vsize_819, VariableAccess target_18) {
		target_18.getTarget()=vsize_819
}

predicate func_19(Parameter vlen_808, VariableAccess target_19) {
		target_19.getTarget()=vlen_808
}

predicate func_21(Parameter vctxt_807, Parameter vlen_808, Variable vsize_819, AddExpr target_21) {
		target_21.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lasttsize"
		and target_21.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_21.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_808
		and target_21.getAnOperand() instanceof Literal
		and target_21.getParent().(AssignExpr).getRValue() = target_21
		and target_21.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_819
}

predicate func_22(Variable vsize_819, AssignMulExpr target_22) {
		target_22.getLValue().(VariableAccess).getTarget()=vsize_819
		and target_22.getRValue() instanceof Literal
}

predicate func_23(Variable vsize_819, BlockStmt target_23) {
		target_23.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_819
		and target_23.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof AddExpr
		and target_23.getStmt(3).(ExprStmt).getExpr() instanceof AssignMulExpr
		and target_23.getStmt(4) instanceof ExprStmt
		and target_23.getStmt(5) instanceof IfStmt
}

predicate func_24(Parameter vctxt_807, RelationalOperation target_24) {
		 (target_24 instanceof GEExpr or target_24 instanceof LEExpr)
		and target_24.getGreaterOperand() instanceof AddExpr
		and target_24.getLesserOperand().(PointerFieldAccess).getTarget().getName()="lasttsize"
		and target_24.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
}

predicate func_26(Parameter vctxt_807, Parameter vtarget_807, EqualityOperation target_26) {
		target_26.getAnOperand().(PointerFieldAccess).getTarget().getName()="lasttext"
		and target_26.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_807
		and target_26.getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_26.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_807
}

predicate func_27(Parameter vctxt_807, Parameter vtarget_807, ExprStmt target_27) {
		target_27.getExpr().(FunctionCall).getTarget().hasName("xsltTransformError")
		and target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_807
		and target_27.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_27.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtarget_807
		and target_27.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="xsltCopyText: text allocation failed\n"
}

from Function func, Parameter vctxt_807, Parameter vtarget_807, Parameter vlen_808, Variable vnewbuf_818, Variable vsize_819, Variable vxmlRealloc, Literal target_0, DeclStmt target_7, DeclStmt target_8, ExprStmt target_9, IfStmt target_10, ExprStmt target_11, ExprStmt target_12, PointerFieldAccess target_15, ExprStmt target_16, VariableAccess target_17, VariableAccess target_18, VariableAccess target_19, AddExpr target_21, AssignMulExpr target_22, BlockStmt target_23, RelationalOperation target_24, EqualityOperation target_26, ExprStmt target_27
where
func_0(func, target_0)
and not func_1(vctxt_807, target_23, target_24)
and not func_2(vctxt_807, vtarget_807, target_24, target_26, target_9)
and not func_3(target_24, func)
and not func_5(vsize_819)
and not func_6(vctxt_807, vsize_819, target_26, target_27, target_9)
and func_7(target_24, func, target_7)
and func_8(target_24, func, target_8)
and func_9(vtarget_807, vnewbuf_818, vsize_819, vxmlRealloc, target_24, target_9)
and func_10(vctxt_807, vtarget_807, vnewbuf_818, target_24, target_10)
and func_11(vctxt_807, vnewbuf_818, target_24, target_11)
and func_12(vtarget_807, vnewbuf_818, target_24, target_12)
and func_15(vctxt_807, target_15)
and func_16(vctxt_807, vsize_819, target_24, target_16)
and func_17(vsize_819, target_17)
and func_18(vsize_819, target_18)
and func_19(vlen_808, target_19)
and func_21(vctxt_807, vlen_808, vsize_819, target_21)
and func_22(vsize_819, target_22)
and func_23(vsize_819, target_23)
and func_24(vctxt_807, target_24)
and func_26(vctxt_807, vtarget_807, target_26)
and func_27(vctxt_807, vtarget_807, target_27)
and vctxt_807.getType().hasName("xsltTransformContextPtr")
and vtarget_807.getType().hasName("xmlNodePtr")
and vlen_808.getType().hasName("int")
and vnewbuf_818.getType().hasName("xmlChar *")
and vsize_819.getType().hasName("int")
and vxmlRealloc.getType().hasName("xmlReallocFunc")
and vctxt_807.getParentScope+() = func
and vtarget_807.getParentScope+() = func
and vlen_808.getParentScope+() = func
and vnewbuf_818.getParentScope+() = func
and vsize_819.getParentScope+() = func
and not vxmlRealloc.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
