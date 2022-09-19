import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="201"
		and not target_0.getValue()="203"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="217"
		and not target_1.getValue()="219"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="226"
		and not target_2.getValue()="228"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="234"
		and not target_3.getValue()="236"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="263"
		and not target_4.getValue()="265"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="286"
		and not target_5.getValue()="288"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="301"
		and not target_6.getValue()="303"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="317"
		and not target_7.getValue()="319"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="336"
		and not target_8.getValue()="338"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="348"
		and not target_9.getValue()="350"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="372"
		and not target_10.getValue()="374"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="384"
		and not target_11.getValue()="386"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="389"
		and not target_12.getValue()="391"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(Literal target_13 |
		target_13.getValue()="421"
		and not target_13.getValue()="423"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="460"
		and not target_14.getValue()="462"
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="465"
		and not target_15.getValue()="467"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Function func) {
	exists(Literal target_16 |
		target_16.getValue()="485"
		and not target_16.getValue()="487"
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(Function func) {
	exists(Literal target_17 |
		target_17.getValue()="501"
		and not target_17.getValue()="503"
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Parameter vaclass, Function func) {
	exists(DeclStmt target_18 |
		target_18.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("int")
		and target_18.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getType().hasName("int")
		and target_18.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vaclass
		and target_18.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_18.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="10"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18)
}

predicate func_19(Parameter vaclass, Function func) {
	exists(ExprStmt target_19 |
		target_19.getExpr().(AssignAndExpr).getType().hasName("int")
		and target_19.getExpr().(AssignAndExpr).getLValue().(VariableAccess).getTarget()=vaclass
		and target_19.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getType().hasName("int")
		and target_19.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="-1025"
		and target_19.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(LShiftExpr).getType().hasName("int")
		and target_19.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(LShiftExpr).getValue()="1024"
		and target_19.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_19.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="10"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19)
}

predicate func_20(Parameter vpval, Parameter vit, Function func) {
	exists(IfStmt target_20 |
		target_20.getCondition().(EQExpr).getType().hasName("int")
		and target_20.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_20.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ASN1_item_ex_free")
		and target_20.getThen().(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_20.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval
		and target_20.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vit
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20)
}

predicate func_21(Parameter vpval, Parameter vit, Function func) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(FunctionCall).getTarget().hasName("ASN1_item_ex_free")
		and target_21.getExpr().(FunctionCall).getType().hasName("void")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vit
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21)
}

from Function func, Parameter vpval, Parameter vit, Parameter vaclass
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
and func_17(func)
and not func_18(vaclass, func)
and not func_19(vaclass, func)
and not func_20(vpval, vit, func)
and func_21(vpval, vit, func)
and vpval.getType().hasName("ASN1_VALUE **")
and vit.getType().hasName("const ASN1_ITEM *")
and vaclass.getType().hasName("int")
and vpval.getParentScope+() = func
and vit.getParentScope+() = func
and vaclass.getParentScope+() = func
select func, vpval, vit, vaclass
