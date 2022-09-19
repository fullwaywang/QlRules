import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="159"
		and not target_0.getValue()="174"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="174"
		and not target_1.getValue()="189"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="183"
		and not target_2.getValue()="198"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="191"
		and not target_3.getValue()="206"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="214"
		and not target_4.getValue()="229"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="58"
		and not target_5.getValue()="201"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="237"
		and not target_6.getValue()="159"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="249"
		and not target_7.getValue()="264"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="274"
		and not target_8.getValue()="289"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="286"
		and not target_9.getValue()="301"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="291"
		and not target_10.getValue()="306"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="325"
		and not target_11.getValue()="340"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="364"
		and not target_12.getValue()="380"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(Literal target_13 |
		target_13.getValue()="369"
		and not target_13.getValue()="385"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="389"
		and not target_14.getValue()="405"
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="100"
		and not target_15.getValue()="58"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Function func) {
	exists(Literal target_16 |
		target_16.getValue()="405"
		and not target_16.getValue()="252"
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(Function func) {
	exists(IfStmt target_17 |
		target_17.getCondition().(GTExpr).getType().hasName("int")
		and target_17.getCondition().(GTExpr).getGreaterOperand().(PrefixIncrExpr).getType().hasName("int")
		and target_17.getCondition().(GTExpr).getLesserOperand().(Literal).getValue()="30"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="120"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="201"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/asn1/tasn_dec.c"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="159"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17)
}

predicate func_18(Parameter vpval, Parameter vin, Parameter vlen, Parameter vit, Parameter vtag, Parameter vopt, Parameter vctx) {
	exists(BlockStmt target_18 |
		target_18.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_18.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(NEExpr).getType().hasName("int")
		and target_18.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vtag
		and target_18.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(NEExpr).getRightOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_18.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(VariableAccess).getTarget()=vopt
		and target_18.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_18.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_18.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="120"
		and target_18.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="170"
		and target_18.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/asn1/tasn_dec.c"
		and target_18.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="174"
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("asn1_template_ex_d2i")
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getType().hasName("int")
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="templates"
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getType().hasName("const ASN1_TEMPLATE *")
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vopt
		and target_18.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vctx
		and target_18.getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="templates"
		and target_18.getParent().(IfStmt).getCondition().(PointerFieldAccess).getType().hasName("const ASN1_TEMPLATE *")
		and target_18.getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit)
}

predicate func_23(Function func) {
	exists(ExprStmt target_23 |
		target_23.getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_23.getExpr().(FunctionCall).getType().hasName("void")
		and target_23.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_23.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="120"
		and target_23.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="100"
		and target_23.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/asn1/tasn_dec.c"
		and target_23.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="421"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_23)
}

predicate func_24(Parameter vpval, Parameter vin, Parameter vlen, Parameter vit, Parameter vopt, Parameter vctx) {
	exists(ReturnStmt target_24 |
		target_24.getExpr().(FunctionCall).getTarget().hasName("asn1_template_ex_d2i")
		and target_24.getExpr().(FunctionCall).getType().hasName("int")
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval
		and target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin
		and target_24.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen
		and target_24.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="templates"
		and target_24.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getType().hasName("const ASN1_TEMPLATE *")
		and target_24.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit
		and target_24.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vopt
		and target_24.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vctx
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="templates"
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getType().hasName("const ASN1_TEMPLATE *")
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vit)
}

from Function func, Parameter vpval, Parameter vin, Parameter vlen, Parameter vit, Parameter vtag, Parameter vopt, Parameter vctx
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(func)
and func_7(func)
and func_8(func)
and func_9(func)
and func_10(func)
and func_11(func)
and func_12(func)
and func_13(func)
and func_14(func)
and func_15(func)
and func_16(func)
and not func_17(func)
and not func_18(vpval, vin, vlen, vit, vtag, vopt, vctx)
and not func_23(func)
and func_24(vpval, vin, vlen, vit, vopt, vctx)
and vpval.getType().hasName("ASN1_VALUE **")
and vin.getType().hasName("const unsigned char **")
and vlen.getType().hasName("long")
and vit.getType().hasName("const ASN1_ITEM *")
and vtag.getType().hasName("int")
and vopt.getType().hasName("char")
and vctx.getType().hasName("ASN1_TLC *")
and vpval.getParentScope+() = func
and vin.getParentScope+() = func
and vlen.getParentScope+() = func
and vit.getParentScope+() = func
and vtag.getParentScope+() = func
and vopt.getParentScope+() = func
and vctx.getParentScope+() = func
select func, vpval, vin, vlen, vit, vtag, vopt, vctx
