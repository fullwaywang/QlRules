/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_close_open_stateid
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-close-open-stateid
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_close_open_stateid 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_0)
}

predicate func_1(Variable vclp_6684, Variable vreaplist_6686) {
	exists(ForStmt target_1 |
		target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("nfs4_ol_stateid *")
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="next"
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vreaplist_6686
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).toString() = "declaration"
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("void *")
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="st_locks"
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_1.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="st_locks"
		and target_1.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("nfs4_ol_stateid *")
		and target_1.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vreaplist_6686
		and target_1.getUpdate().(AssignExpr).getLValue().(VariableAccess).getType().hasName("nfs4_ol_stateid *")
		and target_1.getUpdate().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="next"
		and target_1.getUpdate().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="st_locks"
		and target_1.getUpdate().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("nfs4_ol_stateid *")
		and target_1.getUpdate().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).toString() = "declaration"
		and target_1.getUpdate().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("void *")
		and target_1.getUpdate().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_1.getUpdate().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="st_locks"
		and target_1.getUpdate().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerArithmeticOperation).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("nfs4_free_cpntf_statelist")
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="net"
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclp_6684
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="st_stid"
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("nfs4_ol_stateid *")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="cl_minorversion"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclp_6684)
}

predicate func_8(Variable vclp_6684) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="cl_lock"
		and target_8.getQualifier().(VariableAccess).getTarget()=vclp_6684)
}

from Function func, Variable vclp_6684, Variable vreaplist_6686
where
not func_0(func)
and not func_1(vclp_6684, vreaplist_6686)
and vclp_6684.getType().hasName("nfs4_client *")
and func_8(vclp_6684)
and vreaplist_6686.getType().hasName("list_head")
and vclp_6684.getParentScope+() = func
and vreaplist_6686.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
