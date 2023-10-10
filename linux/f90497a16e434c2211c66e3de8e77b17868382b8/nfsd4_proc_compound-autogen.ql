/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_proc_compound
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-proc-compound
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_proc_compound 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vargs_2600) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="opcnt"
		and target_0.getQualifier().(VariableAccess).getTarget()=vargs_2600)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2491"
		and not target_1.getValue()="2575"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="16"
		and not target_2.getValue()="50"
		and target_2.getParent().(GTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof PointerFieldAccess
		and target_2.getEnclosingFunction() = func)
}

predicate func_5(Variable vargs_2600) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="client_opcnt"
		and target_5.getQualifier().(VariableAccess).getTarget()=vargs_2600)
}

predicate func_7(Variable vargs_2600, Variable vresp_2601, Variable vop_2602, Variable vcstate_2603) {
	exists(IfStmt target_7 |
		target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="minorversion"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcstate_2603
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="client_opcnt"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_2600
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="opcnt"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresp_2601
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_2602
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_7.getThen().(BlockStmt).getStmt(1) instanceof GotoStmt
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="opcnt"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresp_2601
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="50"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_15(Variable vstatus_2607) {
	exists(VariableAccess target_15 |
		target_15.getTarget()=vstatus_2607
		and target_15.getParent().(AssignExpr).getLValue() = target_15
		and target_15.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_15.getParent().(AssignExpr).getRValue().(FunctionCall).getValue()="572981248")
}

predicate func_16(Variable vargs_2600) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="minorversion"
		and target_16.getQualifier().(VariableAccess).getTarget()=vargs_2600)
}

predicate func_17(Variable vargs_2600) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("check_if_stalefh_allowed")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vargs_2600)
}

predicate func_18(Variable vresp_2601) {
	exists(PointerFieldAccess target_18 |
		target_18.getTarget().getName()="rqstp"
		and target_18.getQualifier().(VariableAccess).getTarget()=vresp_2601)
}

predicate func_19(Variable vresp_2601, Variable vop_2602) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("nfsd4_encode_operation")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vresp_2601
		and target_19.getArgument(1).(VariableAccess).getTarget()=vop_2602)
}

predicate func_20(Variable vcstate_2603) {
	exists(PointerFieldAccess target_20 |
		target_20.getTarget().getName()="minorversion"
		and target_20.getQualifier().(VariableAccess).getTarget()=vcstate_2603)
}

from Function func, Parameter vrqstp_2598, Variable vargs_2600, Variable vresp_2601, Variable vop_2602, Variable vcstate_2603, Variable vstatus_2607
where
func_0(vargs_2600)
and func_1(func)
and func_2(func)
and not func_5(vargs_2600)
and not func_7(vargs_2600, vresp_2601, vop_2602, vcstate_2603)
and func_15(vstatus_2607)
and vrqstp_2598.getType().hasName("svc_rqst *")
and vargs_2600.getType().hasName("nfsd4_compoundargs *")
and func_16(vargs_2600)
and func_17(vargs_2600)
and vresp_2601.getType().hasName("nfsd4_compoundres *")
and func_18(vresp_2601)
and func_19(vresp_2601, vop_2602)
and vop_2602.getType().hasName("nfsd4_op *")
and vcstate_2603.getType().hasName("nfsd4_compound_state *")
and func_20(vcstate_2603)
and vstatus_2607.getType().hasName("__be32")
and vrqstp_2598.getParentScope+() = func
and vargs_2600.getParentScope+() = func
and vresp_2601.getParentScope+() = func
and vop_2602.getParentScope+() = func
and vcstate_2603.getParentScope+() = func
and vstatus_2607.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
