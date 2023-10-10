/**
 * @name linux-7c03e2cda4a584cadc398e8f6641ca9988a39d52-vfs_setxattr
 * @id cpp/linux/7c03e2cda4a584cadc398e8f6641ca9988a39d52/vfs-setxattr
 * @description linux-7c03e2cda4a584cadc398e8f6641ca9988a39d52-vfs_setxattr 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvalue_274, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vvalue_274
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_1(Parameter vdentry_274, Parameter vname_274, Parameter vvalue_274, Parameter vsize_275, Variable verror_279, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vsize_275
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_274
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="security.capability"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_279
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cap_convert_nscap")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdentry_274
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vvalue_274
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_275
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verror_279
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen() instanceof ReturnStmt
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_275
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=verror_279
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1))
}

predicate func_5(Parameter vvalue_274, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvalue_274
		and target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("const void *")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_274
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_5))
}

predicate func_6(Variable verror_279, Function func) {
	exists(ReturnStmt target_6 |
		target_6.getExpr().(VariableAccess).getTarget()=verror_279
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_6))
}

predicate func_8(Parameter vdentry_274) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="d_inode"
		and target_8.getQualifier().(VariableAccess).getTarget()=vdentry_274)
}

predicate func_9(Parameter vdentry_274, Parameter vname_274, Parameter vvalue_274, Parameter vsize_275, Parameter vflags_275, Variable vdelegated_inode_278) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("__vfs_setxattr_locked")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vdentry_274
		and target_9.getArgument(1).(VariableAccess).getTarget()=vname_274
		and target_9.getArgument(2).(VariableAccess).getTarget()=vvalue_274
		and target_9.getArgument(3).(VariableAccess).getTarget()=vsize_275
		and target_9.getArgument(4).(VariableAccess).getTarget()=vflags_275
		and target_9.getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdelegated_inode_278)
}

predicate func_12(Variable verror_279) {
	exists(NotExpr target_12 |
		target_12.getOperand().(VariableAccess).getTarget()=verror_279
		and target_12.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

from Function func, Parameter vdentry_274, Parameter vname_274, Parameter vvalue_274, Parameter vsize_275, Parameter vflags_275, Variable vdelegated_inode_278, Variable verror_279
where
not func_0(vvalue_274, func)
and not func_1(vdentry_274, vname_274, vvalue_274, vsize_275, verror_279, func)
and not func_5(vvalue_274, func)
and not func_6(verror_279, func)
and vdentry_274.getType().hasName("dentry *")
and func_8(vdentry_274)
and vname_274.getType().hasName("const char *")
and vvalue_274.getType().hasName("const void *")
and func_9(vdentry_274, vname_274, vvalue_274, vsize_275, vflags_275, vdelegated_inode_278)
and vsize_275.getType().hasName("size_t")
and vflags_275.getType().hasName("int")
and vdelegated_inode_278.getType().hasName("inode *")
and verror_279.getType().hasName("int")
and func_12(verror_279)
and vdentry_274.getParentScope+() = func
and vname_274.getParentScope+() = func
and vvalue_274.getParentScope+() = func
and vsize_275.getParentScope+() = func
and vflags_275.getParentScope+() = func
and vdelegated_inode_278.getParentScope+() = func
and verror_279.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
