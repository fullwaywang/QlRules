import cpp

predicate func_0(Parameter vin, Parameter vinl, Parameter vctx) {
	exists(GTExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getGreaterOperand().(SubExpr).getType().hasName("int")
		and target_0.getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_0.getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("int")
		and target_0.getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_0.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="num"
		and target_0.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getType().hasName("int")
		and target_0.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vinl
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="enc_data"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="num"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinl
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vinl)
}

predicate func_1(Parameter vctx) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="num"
		and target_1.getType().hasName("int")
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx)
}

predicate func_2(Parameter vctx) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="length"
		and target_2.getType().hasName("int")
		and target_2.getQualifier().(VariableAccess).getTarget()=vctx)
}

predicate func_4(Parameter vin, Parameter vinl, Parameter vctx, Function func) {
	exists(LTExpr target_4 |
		target_4.getType().hasName("int")
		and target_4.getLesserOperand().(AddExpr).getType().hasName("int")
		and target_4.getLesserOperand().(AddExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_4.getLesserOperand().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vinl
		and target_4.getGreaterOperand() instanceof PointerFieldAccess
		and target_4.getEnclosingFunction() = func
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="enc_data"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="num"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinl
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vinl)
}

from Function func, Parameter vin, Parameter vinl, Parameter vctx
where
not func_0(vin, vinl, vctx)
and func_1(vctx)
and func_2(vctx)
and func_4(vin, vinl, vctx, func)
and vin.getType().hasName("const unsigned char *")
and vinl.getType().hasName("int")
and vctx.getType().hasName("EVP_ENCODE_CTX *")
and vin.getParentScope+() = func
and vinl.getParentScope+() = func
and vctx.getParentScope+() = func
select func, vin, vinl, vctx
