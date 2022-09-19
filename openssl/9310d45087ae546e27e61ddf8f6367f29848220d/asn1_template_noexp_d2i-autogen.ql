import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="629"
		and not target_0.getValue()="649"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="648"
		and not target_1.getValue()="668"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="660"
		and not target_2.getValue()="680"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="58"
		and not target_3.getValue()="137"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="671"
		and not target_4.getValue()="702"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="677"
		and not target_5.getValue()="697"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="682"
		and not target_6.getValue()="702"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="691"
		and not target_7.getValue()="710"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="700"
		and not target_8.getValue()="720"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vlen, Parameter vtt, Parameter vctx, Variable vp, Variable vskfield) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("ASN1_item_ex_d2i")
		and not target_9.getTarget().hasName("asn1_item_ex_d2i")
		and target_9.getType().hasName("int")
		and target_9.getArgument(0).(AddressOfExpr).getType().hasName("ASN1_VALUE **")
		and target_9.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vskfield
		and target_9.getArgument(1).(AddressOfExpr).getType().hasName("const unsigned char **")
		and target_9.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp
		and target_9.getArgument(2).(VariableAccess).getTarget()=vlen
		and target_9.getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_9.getArgument(3).(PointerFieldAccess).getType().hasName("ASN1_ITEM_EXP *")
		and target_9.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt
		and target_9.getArgument(4).(UnaryMinusExpr).getType().hasName("int")
		and target_9.getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_9.getArgument(4).(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_9.getArgument(5).(Literal).getValue()="0"
		and target_9.getArgument(6).(Literal).getValue()="0"
		and target_9.getArgument(7).(VariableAccess).getTarget()=vctx)
}

predicate func_10(Parameter vval, Parameter vlen, Parameter vtt, Parameter vopt, Parameter vctx, Variable vaclass, Variable vp) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("ASN1_item_ex_d2i")
		and not target_10.getTarget().hasName("asn1_item_ex_d2i")
		and target_10.getType().hasName("int")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vval
		and target_10.getArgument(1).(AddressOfExpr).getType().hasName("const unsigned char **")
		and target_10.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp
		and target_10.getArgument(2).(VariableAccess).getTarget()=vlen
		and target_10.getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_10.getArgument(3).(PointerFieldAccess).getType().hasName("ASN1_ITEM_EXP *")
		and target_10.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt
		and target_10.getArgument(4).(PointerFieldAccess).getTarget().getName()="tag"
		and target_10.getArgument(4).(PointerFieldAccess).getType().hasName("long")
		and target_10.getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt
		and target_10.getArgument(5).(VariableAccess).getTarget()=vaclass
		and target_10.getArgument(6).(VariableAccess).getTarget()=vopt
		and target_10.getArgument(7).(VariableAccess).getTarget()=vctx)
}

predicate func_11(Parameter vval, Parameter vlen, Parameter vtt, Parameter vopt, Parameter vctx, Variable vp) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("ASN1_item_ex_d2i")
		and not target_11.getTarget().hasName("asn1_item_ex_d2i")
		and target_11.getType().hasName("int")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vval
		and target_11.getArgument(1).(AddressOfExpr).getType().hasName("const unsigned char **")
		and target_11.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp
		and target_11.getArgument(2).(VariableAccess).getTarget()=vlen
		and target_11.getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_11.getArgument(3).(PointerFieldAccess).getType().hasName("ASN1_ITEM_EXP *")
		and target_11.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt
		and target_11.getArgument(4).(UnaryMinusExpr).getType().hasName("int")
		and target_11.getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_11.getArgument(4).(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_11.getArgument(5).(BitwiseAndExpr).getType().hasName("unsigned long")
		and target_11.getArgument(5).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_11.getArgument(5).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("unsigned long")
		and target_11.getArgument(5).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt
		and target_11.getArgument(5).(BitwiseAndExpr).getRightOperand().(LShiftExpr).getType().hasName("int")
		and target_11.getArgument(5).(BitwiseAndExpr).getRightOperand().(LShiftExpr).getValue()="1024"
		and target_11.getArgument(5).(BitwiseAndExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_11.getArgument(5).(BitwiseAndExpr).getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="10"
		and target_11.getArgument(6).(VariableAccess).getTarget()=vopt
		and target_11.getArgument(7).(VariableAccess).getTarget()=vctx)
}

predicate func_14(Variable vret) {
	exists(BlockStmt target_14 |
		target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="131"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="58"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="tasn_dec.c"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="710"
		and target_14.getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_14.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vret)
}

predicate func_16(Parameter vval, Parameter vlen, Parameter vtt, Parameter vopt, Parameter vctx, Variable vflags, Variable vret, Variable vp) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(AssignExpr).getType().hasName("int")
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("asn1_item_ex_d2i")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("int")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vval
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getType().hasName("const unsigned char **")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getType().hasName("ASN1_ITEM_EXP *")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(UnaryMinusExpr).getType().hasName("int")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(BitwiseAndExpr).getType().hasName("unsigned long")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(BitwiseAndExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(BitwiseAndExpr).getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="10"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vopt
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vctx
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getType().hasName("int")
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="3")
}

from Function func, Parameter vval, Parameter vlen, Parameter vtt, Parameter vopt, Parameter vctx, Variable vflags, Variable vaclass, Variable vret, Variable vp, Variable vskfield
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
and func_9(vlen, vtt, vctx, vp, vskfield)
and func_10(vval, vlen, vtt, vopt, vctx, vaclass, vp)
and func_11(vval, vlen, vtt, vopt, vctx, vp)
and not func_14(vret)
and not func_16(vval, vlen, vtt, vopt, vctx, vflags, vret, vp)
and vval.getType().hasName("ASN1_VALUE **")
and vlen.getType().hasName("long")
and vtt.getType().hasName("const ASN1_TEMPLATE *")
and vopt.getType().hasName("char")
and vctx.getType().hasName("ASN1_TLC *")
and vflags.getType().hasName("int")
and vaclass.getType().hasName("int")
and vret.getType().hasName("int")
and vp.getType().hasName("const unsigned char *")
and vskfield.getType().hasName("ASN1_VALUE *")
and vval.getParentScope+() = func
and vlen.getParentScope+() = func
and vtt.getParentScope+() = func
and vopt.getParentScope+() = func
and vctx.getParentScope+() = func
and vflags.getParentScope+() = func
and vaclass.getParentScope+() = func
and vret.getParentScope+() = func
and vp.getParentScope+() = func
and vskfield.getParentScope+() = func
select func, vval, vlen, vtt, vopt, vctx, vflags, vaclass, vret, vp, vskfield
