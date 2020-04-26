namespace BankApplication.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class tempShare : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.AspNetUsers", "TempShare1", c => c.String());
            AddColumn("dbo.AspNetUsers", "TempShare2", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.AspNetUsers", "TempShare2");
            DropColumn("dbo.AspNetUsers", "TempShare1");
        }
    }
}
