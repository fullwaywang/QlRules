import cpp

predicate func_0(Parameter vdsa, Variable vq_bits) {
	exists(AddExpr target_0 |
		target_0.getType().hasName("unsigned long")
		and target_0.getLeftOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_0.getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_0.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_0.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_0.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa
		and target_0.getRightOperand().(MulExpr).getType().hasName("unsigned long")
		and target_0.getRightOperand().(MulExpr).getValue()="128"
		and target_0.getRightOperand().(MulExpr).getLeftOperand().(SizeofExprOperator).getType().hasName("unsigned long")
		and target_0.getRightOperand().(MulExpr).getLeftOperand().(SizeofExprOperator).getValue()="8"
		and target_0.getRightOperand().(MulExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getType().hasName("unsigned long")
		and target_0.getRightOperand().(MulExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getRightOperand().(MulExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="q"
		and target_0.getRightOperand().(MulExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa
		and target_0.getRightOperand().(MulExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getRightOperand().(MulExpr).getRightOperand().(Literal).getValue()="16"
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_bits)
}

predicate func_1(Parameter vdsa) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("BN_num_bits")
		and target_1.getType().hasName("int")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_1.getArgument(0).(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa)
}

from Function func, Parameter vdsa, Variable vq_bits
where
not func_0(vdsa, vq_bits)
and func_1(vdsa)
and vdsa.getType().hasName("DSA *")
and vq_bits.getType().hasName("int")
and vdsa.getParentScope+() = func
and vq_bits.getParentScope+() = func
select func, vdsa, vq_bits
