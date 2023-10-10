/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_create_session
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-create-session
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_create_session 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsess_1634) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("__memset")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vsess_1634
		and target_0.getArgument(1).(Literal).getValue()="0"
		and target_0.getArgument(2).(SizeofExprOperator).getValue()="112"
		and target_0.getArgument(2).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsess_1634)
}

predicate func_1(Parameter vsess_1634, Parameter vargp_1633) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("nfsd4_decode_cb_sec")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vargp_1633
		and target_1.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cb_sec"
		and target_1.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsess_1634)
}

predicate func_2(Variable vstatus_1636) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vstatus_1636
		and target_2.getRValue() instanceof FunctionCall)
}

predicate func_3(Variable vstatus_1636, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getTarget()=vstatus_1636
		and target_3.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vstatus_1636
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Function func) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("__builtin_bswap32")
		and target_4.getValue()="0"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vsess_1634) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="callback_prog"
		and target_5.getQualifier().(VariableAccess).getTarget()=vsess_1634)
}

from Function func, Parameter vsess_1634, Variable vstatus_1636, Parameter vargp_1633
where
not func_0(vsess_1634)
and func_1(vsess_1634, vargp_1633)
and func_2(vstatus_1636)
and func_3(vstatus_1636, func)
and func_4(func)
and vsess_1634.getType().hasName("nfsd4_create_session *")
and func_5(vsess_1634)
and vstatus_1636.getType().hasName("__be32")
and vargp_1633.getType().hasName("nfsd4_compoundargs *")
and vsess_1634.getParentScope+() = func
and vstatus_1636.getParentScope+() = func
and vargp_1633.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
