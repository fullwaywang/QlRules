/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_cb_offload_done
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-cb-offload-done
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_cb_offload_done 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcb_1621, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vcb_1621
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).toString() = "declaration"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("void *")
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="co_cb"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getStmt(0)=target_0)
}

predicate func_4(Parameter vtask_1622, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("trace_nfsd_cb_offload_done")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="cb_stateid"
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="co_res"
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("nfsd4_cb_offload *")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtask_1622
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_4))
}

from Function func, Parameter vcb_1621, Parameter vtask_1622
where
not func_0(vcb_1621, func)
and not func_4(vtask_1622, func)
and vcb_1621.getType().hasName("nfsd4_callback *")
and vtask_1622.getType().hasName("rpc_task *")
and vcb_1621.getParentScope+() = func
and vtask_1622.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
