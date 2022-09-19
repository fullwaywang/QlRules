import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="157"
		and not target_0.getValue()="158"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="167"
		and not target_1.getValue()="168"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="172"
		and not target_2.getValue()="173"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="177"
		and not target_3.getValue()="178"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="204"
		and not target_4.getValue()="205"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="222"
		and not target_5.getValue()="225"
		and target_5.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="226"
		and not target_7.getValue()="238"
		and target_7.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="233"
		and not target_10.getValue()="246"
		and target_10.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="245"
		and not target_12.getValue()="261"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(Literal target_13 |
		target_13.getValue()="257"
		and not target_13.getValue()="273"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Variable vwant, Variable voff, Variable vlen) {
	exists(DeclStmt target_14 |
		target_14.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("size_t")
		and target_14.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(MulExpr).getType().hasName("int")
		and target_14.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(MulExpr).getValue()="16384"
		and target_14.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(MulExpr).getLeftOperand().(Literal).getValue()="16"
		and target_14.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(MulExpr).getRightOperand().(Literal).getValue()="1024"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getType().hasName("int")
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vwant
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff)
}

predicate func_15(Parameter vin, Variable vb, Variable vi, Variable vwant, Variable voff, Variable vlen) {
	exists(WhileStmt target_15 |
		target_15.getCondition().(GTExpr).getType().hasName("int")
		and target_15.getCondition().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vwant
		and target_15.getCondition().(GTExpr).getLesserOperand().(Literal).getValue()="0"
		and target_15.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("size_t")
		and target_15.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vwant
		and target_15.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vwant
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BUF_MEM_grow_clean")
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vlen
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="107"
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1"
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/asn1/a_d2i_fp.c"
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="238"
		and target_15.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getType().hasName("size_t")
		and target_15.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vwant
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(GTExpr).getType().hasName("int")
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(GTExpr).getLesserOperand().(Literal).getValue()="0"
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BIO_read")
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vi
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="107"
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="142"
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/asn1/a_d2i_fp.c"
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="246"
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vi
		and target_15.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vi
		and target_15.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LTExpr).getType().hasName("int")
		and target_15.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LTExpr).getGreaterOperand().(DivExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_15.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LTExpr).getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="2"
		and target_15.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignMulExpr).getRValue().(Literal).getValue()="2"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getType().hasName("int")
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vwant
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff)
}

from Function func, Parameter vin, Variable vb, Variable vi, Variable vwant, Variable voff, Variable vlen
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_7(func)
and func_10(func)
and func_12(func)
and func_13(func)
and not func_14(vwant, voff, vlen)
and not func_15(vin, vb, vi, vwant, voff, vlen)
and vin.getType().hasName("BIO *")
and vb.getType().hasName("BUF_MEM *")
and vi.getType().hasName("int")
and vwant.getType().hasName("size_t")
and voff.getType().hasName("size_t")
and vlen.getType().hasName("size_t")
and vin.getParentScope+() = func
and vb.getParentScope+() = func
and vi.getParentScope+() = func
and vwant.getParentScope+() = func
and voff.getParentScope+() = func
and vlen.getParentScope+() = func
select func, vin, vb, vi, vwant, voff, vlen
