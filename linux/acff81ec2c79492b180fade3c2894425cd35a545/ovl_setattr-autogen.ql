/**
 * @name linux-acff81ec2c79492b180fade3c2894425cd35a545-ovl_setattr
 * @id cpp/linux/acff81ec2c79492b180fade3c2894425cd35a545/ovl-setattr
 * @description linux-acff81ec2c79492b180fade3c2894425cd35a545-ovl_setattr 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vattr_43, Parameter vdentry_43) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ovl_copy_up_last")
		and not target_0.getTarget().hasName("ovl_copy_up")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdentry_43
		and target_0.getArgument(1).(VariableAccess).getTarget()=vattr_43)
}

predicate func_1(Parameter vattr_43, Variable verr_45, Variable vupperdentry_46) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=verr_45
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mutex"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_inode"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupperdentry_46
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_45
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("notify_change")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vupperdentry_46
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vattr_43
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0")
}

predicate func_2(Variable vupperdentry_46, Parameter vdentry_43, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vupperdentry_46
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ovl_dentry_upper")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdentry_43
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Parameter vattr_43, Variable verr_45, Variable vupperdentry_46) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vupperdentry_46
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mutex"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_inode"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupperdentry_46
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_45
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("notify_change")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vupperdentry_46
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vattr_43
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0")
}

predicate func_4(Variable verr_45, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(VariableAccess).getTarget()=verr_45
		and target_4.getThen().(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Parameter vattr_43, Variable verr_45, Variable vupperdentry_46, Parameter vdentry_43
where
func_0(vattr_43, vdentry_43)
and not func_1(vattr_43, verr_45, vupperdentry_46)
and func_2(vupperdentry_46, vdentry_43, func)
and func_3(vattr_43, verr_45, vupperdentry_46)
and vattr_43.getType().hasName("iattr *")
and verr_45.getType().hasName("int")
and func_4(verr_45, func)
and vupperdentry_46.getType().hasName("dentry *")
and vdentry_43.getType().hasName("dentry *")
and vattr_43.getParentScope+() = func
and verr_45.getParentScope+() = func
and vupperdentry_46.getParentScope+() = func
and vdentry_43.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
