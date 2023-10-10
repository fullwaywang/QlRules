/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_setattr
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd-setattr
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_setattr 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vdentry_354, Variable vhost_err_360, Variable vsize_attr_425) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vhost_err_360
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("notify_change")
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdentry_354
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsize_attr_425
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0")
}

predicate func_6(Parameter vrqstp_350, Variable vdentry_354, Variable vinode_355, Variable viap_356, Variable vhost_err_360) {
	exists(ForStmt target_6 |
		target_6.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_6.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhost_err_360
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__nfsd_setattr")
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdentry_354
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=viap_356
		and target_6.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhost_err_360
		and target_6.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="11"
		and target_6.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_6.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_6.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("nfsd_wait_for_delegreturn")
		and target_6.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrqstp_350
		and target_6.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinode_355
		and target_6.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BreakStmt).toString() = "break;")
}

predicate func_11(Variable vinit_user_ns) {
	exists(AddressOfExpr target_11 |
		target_11.getOperand().(VariableAccess).getTarget()=vinit_user_ns
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall)
}

predicate func_16(Function func) {
	exists(Literal target_16 |
		target_16.getValue()="1"
		and target_16.getEnclosingFunction() = func)
}

predicate func_18(Function func) {
	exists(LabelStmt target_18 |
		target_18.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18)
}

predicate func_19(Function func) {
	exists(Initializer target_19 |
		target_19.getExpr().(Literal).getValue()="0"
		and target_19.getExpr().getEnclosingFunction() = func)
}

predicate func_24(Variable vsize_attr_425) {
	exists(VariableAccess target_24 |
		target_24.getTarget()=vsize_attr_425)
}

predicate func_26(Variable viap_356, Variable vsize_change_362) {
	exists(ExprStmt target_26 |
		target_26.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ia_valid"
		and target_26.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viap_356
		and target_26.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="4294967287"
		and target_26.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getValue()="8"
		and target_26.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_26.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vsize_change_362)
}

predicate func_27(Variable viap_356, Variable vsize_change_362) {
	exists(IfStmt target_27 |
		target_27.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ia_valid"
		and target_27.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viap_356
		and target_27.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="4294967263"
		and target_27.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_27.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="5"
		and target_27.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_27.getThen().(GotoStmt).toString() = "goto ..."
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vsize_change_362)
}

predicate func_28(Variable vdentry_354, Variable viap_356, Variable vhost_err_360, Function func) {
	exists(IfStmt target_28 |
		target_28.getCondition().(PointerFieldAccess).getTarget().getName()="ia_valid"
		and target_28.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viap_356
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ia_valid"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viap_356
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="6"
		and target_28.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhost_err_360
		and target_28.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("notify_change")
		and target_28.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_28.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdentry_354
		and target_28.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=viap_356
		and target_28.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_28)
}

predicate func_31(Parameter vrqstp_350, Parameter vfhp_350, Variable viap_356) {
	exists(FunctionCall target_31 |
		target_31.getTarget().hasName("nfsd_get_write_access")
		and target_31.getArgument(0).(VariableAccess).getTarget()=vrqstp_350
		and target_31.getArgument(1).(VariableAccess).getTarget()=vfhp_350
		and target_31.getArgument(2).(VariableAccess).getTarget()=viap_356)
}

predicate func_32(Variable vinode_355) {
	exists(FunctionCall target_32 |
		target_32.getTarget().hasName("inode_lock")
		and target_32.getArgument(0).(VariableAccess).getTarget()=vinode_355)
}

from Function func, Parameter vrqstp_350, Parameter vfhp_350, Variable vdentry_354, Variable vinode_355, Variable viap_356, Variable vhost_err_360, Variable vsize_change_362, Variable vsize_attr_425, Variable vinit_user_ns
where
func_2(vdentry_354, vhost_err_360, vsize_attr_425)
and not func_6(vrqstp_350, vdentry_354, vinode_355, viap_356, vhost_err_360)
and func_11(vinit_user_ns)
and func_16(func)
and func_18(func)
and func_19(func)
and func_24(vsize_attr_425)
and func_26(viap_356, vsize_change_362)
and func_27(viap_356, vsize_change_362)
and func_28(vdentry_354, viap_356, vhost_err_360, func)
and vrqstp_350.getType().hasName("svc_rqst *")
and func_31(vrqstp_350, vfhp_350, viap_356)
and vfhp_350.getType().hasName("svc_fh *")
and vdentry_354.getType().hasName("dentry *")
and vinode_355.getType().hasName("inode *")
and func_32(vinode_355)
and viap_356.getType().hasName("iattr *")
and vhost_err_360.getType().hasName("int")
and vsize_change_362.getType().hasName("bool")
and vinit_user_ns.getType().hasName("user_namespace")
and vrqstp_350.getParentScope+() = func
and vfhp_350.getParentScope+() = func
and vdentry_354.getParentScope+() = func
and vinode_355.getParentScope+() = func
and viap_356.getParentScope+() = func
and vhost_err_360.getParentScope+() = func
and vsize_change_362.getParentScope+() = func
and vsize_attr_425.getParentScope+() = func
and not vinit_user_ns.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
